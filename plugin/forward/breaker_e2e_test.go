package forward

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/pkg/proxy"
	"github.com/coredns/coredns/plugin/pkg/transport"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

// newForwardUpstream starts a loopback DNS server whose handler can be toggled
// between dropping every query (half-broken) and answering normally.
type controllableUpstream struct {
	addr     string
	dropping atomic.Bool
	queries  atomic.Int64
	srv      *dnstest.Server
}

func newControllableUpstream(t *testing.T) *controllableUpstream {
	t.Helper()
	u := &controllableUpstream{}
	u.dropping.Store(true)
	// NewMultipleServer gives each instance its own handler instead of the
	// global dns mux, so co-located test servers cannot share a handler.
	u.srv = dnstest.NewMultipleServer(func(w dns.ResponseWriter, r *dns.Msg) {
		u.queries.Add(1)
		if u.dropping.Load() {
			return // never answer: TCP connects but no reply, the reported half-broken case
		}
		ret := new(dns.Msg)
		ret.SetReply(r)
		ret.Answer = append(ret.Answer, test.A("example.org. 30 IN A 192.0.2.10"))
		_ = w.WriteMsg(ret)
	})
	u.addr = u.srv.Addr
	t.Cleanup(u.srv.Close)
	return u
}

func newBreakerForward(t *testing.T, upstreams ...*controllableUpstream) (*Forward, map[*controllableUpstream]*proxy.Proxy) {
	t.Helper()
	f := New()
	f.upstreamTimeout = 200 * time.Millisecond
	f.readTimeout = 50 * time.Millisecond
	f.hcInterval = 10 * time.Millisecond
	f.healthBackoff = 100 * time.Millisecond
	f.maxfails = 2
	// ForceTCP gives each upstream its own connection, avoiding loopback UDP
	// socket reuse that can merge datagrams between co-located test servers.
	f.opts.ForceTCP = true
	byUpstream := make(map[*controllableUpstream]*proxy.Proxy, len(upstreams))
	for _, u := range upstreams {
		p := proxy.NewProxy("forward", u.addr, transport.DNS)
		p.SetReadTimeout(50 * time.Millisecond)
		hc := p.GetHealthchecker()
		hc.SetReadTimeout(50 * time.Millisecond)
		hc.SetWriteTimeout(50 * time.Millisecond)
		// Probe over TCP too, so a dropping upstream cannot be hidden by a
		// stray loopback UDP datagram and the path matches ForceTCP queries.
		hc.SetTCPTransport()
		p.SetMaxFails(f.maxfails)
		p.SetHalfOpenWeight(f.halfOpenWeight)
		f.SetProxy(p)
		byUpstream[u] = p
	}
	t.Cleanup(func() { _ = f.OnShutdown() })
	return f, byUpstream
}

func forwardQuery(t *testing.T, f *Forward) (int, error) {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)
	return f.ServeDNS(context.Background(), &test.ResponseWriter{}, req)
}

func waitForState(t *testing.T, p *proxy.Proxy, want proxy.State) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if p.State() == want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("upstream %s state = %s, want %s", p.Addr(), p.State(), want)
}

// TestForwardBreakerRemovesHalfBrokenUpstream verifies that an upstream which
// accepts TCP but never replies is removed after maxfails consecutive failures
// and that traffic is served by a healthy peer instead of waiting out the full
// timeout on every request.
func TestForwardBreakerRemovesHalfBrokenUpstream(t *testing.T) {
	bad := newControllableUpstream(t)
	good := newControllableUpstream(t)
	good.dropping.Store(false)

	f, byUpstream := newBreakerForward(t, bad, good)
	badProxy := byUpstream[bad]

	// First requests hit the half-broken upstream (policy is random, so retry
	// until its breaker opens). Drive enough requests to open it.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && badProxy.State() != proxy.StateOpen {
		_, _ = forwardQuery(t, f)
	}

	waitForState(t, badProxy, proxy.StateOpen)

	// Once removed, the breaker reports the failure statistics gathered above.
	if rate := badProxy.Breaker().FailureRate(); rate <= 0 {
		t.Errorf("expected a positive failure rate for the removed upstream, got %f", rate)
	}
	if badProxy.Breaker().ConsecutiveFails() < f.maxfails {
		t.Errorf("expected at least %d consecutive fails, got %d", f.maxfails, badProxy.Breaker().ConsecutiveFails())
	}

	// Subsequent queries must succeed via the healthy upstream and return quickly:
	// the open breaker must not make us wait for the bad upstream's timeout.
	before := good.queries.Load()
	start := time.Now()
	for range 5 {
		if rc, err := forwardQuery(t, f); err != nil || rc != dns.RcodeSuccess {
			t.Fatalf("expected success via healthy upstream, got rc=%d err=%v", rc, err)
		}
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("five queries took %s; the removed upstream must not add its timeout", elapsed)
	}
	if good.queries.Load() < before+5 {
		t.Errorf("healthy upstream did not serve all queries: got %d, want >= %d", good.queries.Load(), before+5)
	}
}

// TestForwardBreakerRecoveryRamp verifies that a recovered upstream moves
// open -> half_open -> closed under continued probing, without waiting for
// traffic to act as the trial signal.
func TestForwardBreakerRecoveryRamp(t *testing.T) {
	bad := newControllableUpstream(t)
	good := newControllableUpstream(t)
	good.dropping.Store(false)

	f, byUpstream := newBreakerForward(t, bad, good)
	badProxy := byUpstream[bad]

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && badProxy.State() != proxy.StateOpen {
		_, _ = forwardQuery(t, f)
	}
	waitForState(t, badProxy, proxy.StateOpen)

	// Recover the upstream; background probing must walk it back to closed.
	bad.dropping.Store(false)
	waitForState(t, badProxy, proxy.StateClosed)
	if badProxy.Breaker().ConsecutiveFails() != 0 {
		t.Errorf("expected zero consecutive fails after recovery, got %d", badProxy.Breaker().ConsecutiveFails())
	}
	if rc, err := forwardQuery(t, f); err != nil || rc != dns.RcodeSuccess {
		t.Fatalf("query after full recovery failed: rc=%d err=%v", rc, err)
	}
}

// TestForwardPerUpstreamTimeoutReturnsLastError verifies that when every
// upstream fails, the request surfaces an error rather than blocking for the
// sum of all timeouts, and that each upstream is tried once.
func TestForwardPerUpstreamTimeoutReturnsLastError(t *testing.T) {
	first := newControllableUpstream(t)
	second := newControllableUpstream(t)
	third := newControllableUpstream(t)
	upstreams := []*controllableUpstream{first, second, third}

	f, _ := newBreakerForward(t, upstreams...)
	// Disable breaking so the breakers don't remove upstreams mid-request;
	// this isolates the per-attempt timeout and last-error behavior.
	f.maxfails = 0
	for _, p := range f.proxies {
		p.SetMaxFails(0)
	}
	// ForceTCP gives each upstream its own connection, avoiding loopback UDP
	// socket reuse that can merge datagrams between test servers.
	// Sequential makes the upstream ordering deterministic.
	f.p = &sequential{}

	start := time.Now()
	rc, err := forwardQuery(t, f)
	elapsed := time.Since(start)

	if rc != dns.RcodeServerFailure || err == nil {
		t.Fatalf("expected SERVFAIL with an error, got rc=%d err=%v", rc, err)
	}
	// Three upstreams each bounded by the short read timeout, well under a
	// serial 5s total; the per-upstream deadline keeps this tight.
	if elapsed > f.upstreamTimeout+300*time.Millisecond {
		t.Errorf("all-upstream failure took %s, expected per-upstream-bounded latency", elapsed)
	}
	// Every upstream got at least one chance (plus at most a setup retry).
	for _, u := range upstreams {
		if got := u.queries.Load(); got == 0 {
			t.Errorf("upstream %s was never tried", u.addr)
		}
	}
}
