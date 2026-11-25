// Package forward implements a DNS forwarding proxy. It reuses upstream
// connections across DNS, DoT, DoH, and DoQ transports and uses in-band
// health checking.
package forward

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"slices"
	"sync/atomic"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/debug"
	"github.com/coredns/coredns/plugin/dnstap"
	"github.com/coredns/coredns/plugin/metadata"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	proxyPkg "github.com/coredns/coredns/plugin/pkg/proxy"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
	ot "github.com/opentracing/opentracing-go"
	otext "github.com/opentracing/opentracing-go/ext"
)

var log = clog.NewWithPlugin("forward")

const (
	defaultExpire                     = 10 * time.Second
	defaultReadTimeout                = 2 * time.Second
	defaultUpstreamTimeout            = 5 * time.Second
	defaultHalfOpenWeight             = 10
	defaultHealthBackoff              = 30 * time.Second
	hcInterval                        = 500 * time.Millisecond
	defaultConnectAttemptsPerUpstream = 2
)

// Forward represents a plugin instance that can proxy requests to another (DNS) server. It has a list
// of proxies each representing one upstream proxy.
type Forward struct {
	concurrent int64 // atomic counters need to be first in struct for proper alignment

	proxies     []*proxyPkg.Proxy
	p           Policy
	hcInterval  time.Duration
	startFailed bool

	from    string
	ignored []string

	nextAlternateRcodes []int
	nextOnNodata        bool

	tlsConfig                  *tls.Config
	tlsServerName              string
	maxfails                   uint32
	expire                     time.Duration
	maxAge                     time.Duration
	readTimeout                time.Duration
	upstreamTimeout            time.Duration
	halfOpenWeight             uint32
	healthBackoff              time.Duration
	maxIdleConns               int
	dohMethod                  string
	maxConcurrent              int64
	failfastUnhealthyUpstreams bool
	failoverRcodes             []int
	maxConnectAttempts         uint32
	maxConnectAttemptsSet      bool
	sourceAddress              net.IP

	// Hostname resolution fields
	resolver  []string  // custom resolver IPs for hostname TO resolution
	toEntries []toEntry // ordered TO entries preserving config order

	opts proxyPkg.Options // also here for testing

	// ErrLimitExceeded indicates that a query was rejected because the number of concurrent queries has exceeded
	// the maximum allowed (maxConcurrent)
	ErrLimitExceeded error

	tapPlugins []*dnstap.Dnstap // when dnstap plugins are loaded, we use to this to send messages out.

	Next plugin.Handler
}

// New returns a new Forward.
func New() *Forward {
	f := &Forward{
		maxfails:        2,
		tlsConfig:       new(tls.Config),
		expire:          defaultExpire,
		readTimeout:     defaultReadTimeout,
		upstreamTimeout: defaultUpstreamTimeout,
		halfOpenWeight:  defaultHalfOpenWeight,
		healthBackoff:   defaultHealthBackoff,
		p:               new(random),
		from:            ".",
		hcInterval:      hcInterval,
		dohMethod:       http.MethodPost,
		opts:            proxyPkg.Options{ForceTCP: false, PreferUDP: false, HCRecursionDesired: true, HCDomain: "."},
	}
	return f
}

// SetProxy appends p to the proxy list and starts healthchecking.
func (f *Forward) SetProxy(p *proxyPkg.Proxy) {
	f.proxies = append(f.proxies, p)
	p.Start(f.hcInterval)
}

// SetProxyOptions setup proxy options
func (f *Forward) SetProxyOptions(opts proxyPkg.Options) {
	f.opts = opts
}

// SetTapPlugin appends one or more dnstap plugins to the tap plugin list.
func (f *Forward) SetTapPlugin(tapPlugin *dnstap.Dnstap) {
	f.tapPlugins = append(f.tapPlugins, tapPlugin)
	if nextPlugin, ok := tapPlugin.Next.(*dnstap.Dnstap); ok {
		f.SetTapPlugin(nextPlugin)
	}
}

// Len returns the number of configured proxies.
func (f *Forward) Len() int { return len(f.proxies) }

// Name implements plugin.Handler.
func (f *Forward) Name() string { return "forward" }

// ServeDNS implements plugin.Handler.
func (f *Forward) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	if !f.match(state) {
		return plugin.NextOrFailure(f.Name(), f.Next, ctx, w, r)
	}

	if f.maxConcurrent > 0 {
		count := atomic.AddInt64(&(f.concurrent), 1)
		defer atomic.AddInt64(&(f.concurrent), -1)
		if count > f.maxConcurrent {
			maxConcurrentRejectCount.Add(1)
			return dns.RcodeRefused, f.ErrLimitExceeded
		}
	}

	failoverAttempts := 0
	var span, child ot.Span
	var upstreamErr error
	span = ot.SpanFromContext(ctx)

	// The overall retry window bounds the sum of all upstream attempts.
	overallDeadline := time.Now().Add(defaultTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(overallDeadline) {
		overallDeadline = d
	}
	maxConnectAttempts := uint64(f.maxConnectAttempts)
	if !f.maxConnectAttemptsSet {
		maxConnectAttempts = uint64(defaultConnectAttemptsPerUpstream) * uint64(len(f.proxies))
	}
	connectAttempts := uint64(0)
	start := time.Now()

	// tried marks upstreams that already got their chance (including any setup
	// retry), so the same half-broken upstream is never selected twice.
	tried := make(map[*proxyPkg.Proxy]bool, len(f.proxies))

	for time.Now().Before(overallDeadline) && ctx.Err() == nil && (maxConnectAttempts == 0 || connectAttempts < maxConnectAttempts) {
		// Re-evaluate the policy ordering on every pass: a breaker that opens
		// mid-request changes which upstreams are eligible.
		list := f.List()
		var pxy *proxyPkg.Proxy
		untriedExists := false   // an upstream not yet tried in this request
		admittingExists := false // an untried upstream that currently admits traffic
		for _, candidate := range list {
			if tried[candidate] {
				continue
			}
			untriedExists = true
			if f.maxfails != 0 && !candidate.Admit() {
				continue
			}
			admittingExists = true
			if pxy == nil {
				pxy = candidate
			}
		}

		if pxy == nil {
			if !untriedExists || (untriedExists && admittingExists) {
				// Nothing left to try, or every upstream admitting traffic was
				// already tried: fail over rather than re-spraying.
				break
			}
			// All upstreams are currently removed by their breakers.
			healthcheckBrokenCount.Add(1)
			if f.failfastUnhealthyUpstreams {
				break
			}
			// Assume health checking itself is broken and randomly spray one
			// request at an upstream that is not already being retried.
			rnd := new(random).List(f.proxies)
			for _, candidate := range rnd {
				if !tried[candidate] {
					pxy = candidate
					break
				}
			}
			if pxy == nil {
				break
			}
		}
		tried[pxy] = true

		if span != nil {
			child = span.Tracer().StartSpan("connect", ot.ChildOf(span.Context()))
			otext.PeerAddress.Set(child, pxy.Addr())
			ctx = ot.ContextWithSpan(ctx, child)
		}

		metadata.SetValueFunc(ctx, "forward/upstream", func() string {
			return pxy.Addr()
		})

		// Give this attempt its own deadline: the per-upstream timeout, but
		// never past the overall retry window or the caller's deadline.
		attemptDeadline := time.Now().Add(f.upstreamTimeout)
		if attemptDeadline.After(overallDeadline) {
			attemptDeadline = overallDeadline
		}

		// One extra attempt is budgeted for a fresh connection when the first
		// dial or handshake stalls, matching the historical retry semantics.
		allowSetupRetry := maxConnectAttempts == 0 || connectAttempts+1 < maxConnectAttempts

		ret, localAddr, upstreamProto, err := f.exchange(ctx, pxy, state, attemptDeadline, allowSetupRetry)
		connectAttempts++
		if ret == nil && err != nil && errors.Is(err, proxyPkg.ErrSetup) && allowSetupRetry {
			connectAttempts++
		}

		if child != nil {
			child.Finish()
		}

		if len(f.tapPlugins) != 0 {
			toDnstap(ctx, f, pxy.Addr(), localAddr, upstreamProto, state, ret, start)
		}

		upstreamErr = err

		if err != nil {
			if errors.Is(err, proxyPkg.ErrInvalidRequest) {
				return dns.RcodeFormatError, err
			}
			if errors.Is(err, proxyPkg.ErrUnsupportedRequest) {
				return dns.RcodeNotImplemented, err
			}

			// Kick off health check to see if *our* upstream is broken. The
			// breaker itself already recorded the failure via Connect.
			if f.maxfails != 0 {
				pxy.Healthcheck()
			}
			continue
		}

		// Check if the reply is correct; if not return FormErr.
		if !state.Match(ret) {
			debug.Hexdumpf(ret, "Wrong reply for id: %d, %s %d", ret.Id, state.QName(), state.QType())

			formerr := new(dns.Msg)
			formerr.SetRcode(state.Req, dns.RcodeFormatError)
			w.WriteMsg(formerr)
			return 0, nil
		}

		// Check if we have a failover Rcode defined, check if we match on the code
		if slices.Contains(f.failoverRcodes, ret.Rcode) {
			failoverAttempts++
			if failoverAttempts < len(f.proxies) {
				continue
			}
		}

		// Check if we have an alternate Rcode defined, check if we match on the code
		for _, alternateRcode := range f.nextAlternateRcodes {
			if alternateRcode == ret.Rcode && f.Next != nil { // In case we do not have a Next handler, just continue normally
				if _, ok := f.Next.(*Forward); ok { // Only continue if the next forwarder is also a Forworder
					return plugin.NextOrFailure(f.Name(), f.Next, ctx, w, r)
				}
			}
		}

		if f.nextOnNodata && f.Next != nil {
			if ret.Rcode == dns.RcodeSuccess && isEmpty(ret) {
				if _, ok := f.Next.(*Forward); ok {
					return plugin.NextOrFailure(f.Name(), f.Next, ctx, w, r)
				}
			}
		}

		w.WriteMsg(ret)
		return 0, nil
	}

	if upstreamErr != nil {
		return dns.RcodeServerFailure, upstreamErr
	}

	return dns.RcodeServerFailure, ErrNoHealthy
}

// exchange sends the query to one upstream and returns its reply. A failure
// while establishing the connection (dial, TLS/QUIC handshake, stale cached
// connection) is retried once on a fresh connection; failures after the query
// was written, including read timeouts, are returned to the caller for
// failover to another upstream.
func (f *Forward) exchange(ctx context.Context, pxy *proxyPkg.Proxy, state request.Request, deadline time.Time, allowSetupRetry bool) (*dns.Msg, net.Addr, string, error) {
	attemptCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	tlsDeadline := deadline
	tlsConnectTimeout := time.Until(tlsDeadline)
	if allowSetupRetry {
		// Reserve time for a fresh connection if the first TLS handshake stalls.
		tlsConnectTimeout /= 2
	}

	var (
		ret           *dns.Msg
		localAddr     net.Addr
		upstreamProto string
		err           error
	)
	opts := f.opts
	setupRetried := false

	for {
		opts.TLSConnectDeadline = time.Now().Add(tlsConnectTimeout)
		if opts.TLSConnectDeadline.After(tlsDeadline) {
			opts.TLSConnectDeadline = tlsDeadline
		}
		ret, localAddr, upstreamProto, err = pxy.Connect(attemptCtx, state, opts)

		if err == proxyPkg.ErrCachedClosed { // The peer closed a cached TCP or QUIC connection before the query was sent.
			continue
		}
		// A dial or handshake failure happens before the query reaches the
		// upstream, so one fresh-connection retry is safe.
		if err != nil && errors.Is(err, proxyPkg.ErrSetup) && allowSetupRetry && !setupRetried {
			setupRetried = true
			continue
		}
		// Retry with TCP if truncated and prefer_udp configured.
		if ret != nil && ret.Truncated && !opts.ForceTCP && opts.PreferUDP {
			opts.ForceTCP = true
			continue
		}
		break
	}

	return ret, localAddr, upstreamProto, err
}

func (f *Forward) match(state request.Request) bool {
	if !plugin.Name(f.from).Matches(state.Name()) || !f.isAllowedDomain(state.Name()) {
		return false
	}

	return true
}

func (f *Forward) isAllowedDomain(name string) bool {
	if dns.Name(name) == dns.Name(f.from) {
		return true
	}

	for _, ignore := range f.ignored {
		if plugin.Name(ignore).Matches(name) {
			return false
		}
	}
	return true
}

func isEmpty(r *dns.Msg) bool {
	if len(r.Answer) == 0 {
		return true
	}

	for _, r := range r.Answer {
		if r != nil {
			return false
		}
	}
	return true
}

// ForceTCP returns if TCP is forced to be used even when the request comes in over UDP.
func (f *Forward) ForceTCP() bool { return f.opts.ForceTCP }

// PreferUDP returns if UDP is preferred to be used even when the request comes in over TCP.
func (f *Forward) PreferUDP() bool { return f.opts.PreferUDP }

// List returns a set of proxies to be used for this client depending on the policy in f.
func (f *Forward) List() []*proxyPkg.Proxy { return f.p.List(f.proxies) }

var (
	// ErrNoHealthy means no healthy proxies left.
	ErrNoHealthy = errors.New("no healthy proxies")
	// ErrNoForward means no forwarder defined.
	ErrNoForward = errors.New("no forwarder defined")
	// ErrCachedClosed means cached connection was closed by peer.
	ErrCachedClosed = errors.New("cached connection was closed by peer")
)

// Options holds various Options that can be set.
type Options struct {
	// ForceTCP use TCP protocol for upstream DNS request. Has precedence over PreferUDP flag
	ForceTCP bool
	// PreferUDP use UDP protocol for upstream DNS request.
	PreferUDP bool
	// HCRecursionDesired sets recursion desired flag for Proxy healthcheck requests
	HCRecursionDesired bool
	// HCDomain sets domain for Proxy healthcheck requests
	HCDomain string
}

var defaultTimeout = 5 * time.Second
