package proxy

import (
	"crypto/tls"
	"net"
	"net/http"
	"runtime"
	"time"

	"github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/transport"
	"github.com/coredns/coredns/plugin/pkg/up"
)

// Proxy defines an upstream host.
type Proxy struct {
	addr      string
	proxyName string

	transport *Transport
	doq       *doqTransport
	protocol  string

	dohMethod string
	dohHost   string

	readTimeout time.Duration

	// breaker holds the per-upstream failure counters, latency estimate and
	// circuit-breaker state (closed/open/half-open).
	breaker *Breaker

	// health checking
	probe  *up.Probe
	health HealthChecker
}

// NewProxy returns a new proxy.
func NewProxy(proxyName, addr, protocol string) *Proxy {
	p := &Proxy{
		addr:        addr,
		probe:       up.New(),
		readTimeout: 2 * time.Second,
		transport:   newTransport(proxyName, addr),
		protocol:    protocol,
		dohMethod:   http.MethodPost,
		dohHost:     "",
		health:      NewHealthChecker(proxyName, protocol, true, "."),
		proxyName:   proxyName,
	}
	p.breaker = NewBreaker(0)
	p.breaker.onTransition = func(s State) { publishStatus(p.proxyName, p.addr, s) }
	publishStatus(p.proxyName, p.addr, StateClosed)
	if protocol == transport.QUIC {
		p.doq = newDoQTransport(proxyName, addr)
	}

	runtime.SetFinalizer(p, (*Proxy).finalizer)
	return p
}

func (p *Proxy) Addr() string { return p.addr }

// SetTLSConfig sets the TLS config in the lower p.transport and in the healthchecking client.
func (p *Proxy) SetTLSConfig(cfg *tls.Config) {
	p.transport.SetTLSConfig(cfg)
	if p.doq != nil {
		p.doq.setTLSConfig(cfg)
	}
	if p.health != nil {
		p.health.SetTLSConfig(cfg)
	}
	if p.transport.httpClient != nil {
		p.transport.httpClient.Transport.(*http.Transport).TLSClientConfig = cfg
	}
}

// SetExpire sets the expire duration in the lower p.transport.
func (p *Proxy) SetExpire(expire time.Duration) {
	p.transport.SetExpire(expire)
	if p.doq != nil {
		p.doq.setExpire(expire)
	}
}

// SetMaxAge sets the maximum connection lifetime in the lower p.transport.
// A value of 0 (default) disables max-age.
func (p *Proxy) SetMaxAge(maxAge time.Duration) {
	p.transport.SetMaxAge(maxAge)
	if p.doq != nil {
		p.doq.setMaxAge(maxAge)
	}
}

// SetMaxIdleConns sets the maximum idle connections per transport type.
// A value of 0 means unlimited (default).
func (p *Proxy) SetMaxIdleConns(n int) {
	p.transport.SetMaxIdleConns(n)
	if p.transport.httpClient != nil {
		p.transport.httpClient.Transport.(*http.Transport).MaxIdleConns = n
		p.transport.httpClient.Transport.(*http.Transport).MaxIdleConnsPerHost = n
	}
}

func (p *Proxy) SetHTTPClient(client *http.Client) {
	p.transport.httpClient = client
}

func (p *Proxy) SetDOHRequestOptions(method string) {
	p.dohMethod = method
}

func (p *Proxy) SetDOHHost(host string) {
	p.dohHost = host
}

func (p *Proxy) DoHHost() string { return p.dohHost }

func (p *Proxy) GetHealthchecker() HealthChecker {
	return p.health
}

func (p *Proxy) GetTransport() *Transport {
	return p.transport
}

// Breaker returns the proxy's circuit breaker.
func (p *Proxy) Breaker() *Breaker { return p.breaker }

// SetMaxFails configures the number of consecutive failures after which the
// proxy is removed from rotation. A zero maxfails disables circuit breaking and
// keeps the legacy behavior of always considering the proxy healthy.
func (p *Proxy) SetMaxFails(maxfails uint32) {
	p.breaker.maxConsecutiveFails = maxfails
}

// SetHalfOpenWeight configures the share of traffic, in percent, admitted to
// the proxy while it is recovering in the half-open state.
func (p *Proxy) SetHalfOpenWeight(percent uint32) {
	p.breaker.SetHalfOpenWeight(percent)
}

// Fails returns the current consecutive failure count.
func (p *Proxy) Fails() uint32 {
	return p.breaker.ConsecutiveFails()
}

// State returns the circuit-breaker state of the proxy.
func (p *Proxy) State() State {
	return p.breaker.State()
}

// Admit reports whether traffic may be sent to the proxy right now.
func (p *Proxy) Admit() bool {
	return p.breaker.Admit()
}

// Healthcheck starts a health-probe round for this proxy. The probe runs in
// the background and drives circuit recovery to completion:
//
//   - while the breaker is open, a failed check is retried with exponential
//     backoff until the upstream answers;
//   - the first successful check promotes the breaker to half-open, after which
//     checks continue at the base interval until enough consecutive successes
//     close the breaker;
//   - any failure during half-open reopens the breaker and restarts backoff.
//
// A no-op when a round is already in flight or no health checker is configured.
func (p *Proxy) Healthcheck() {
	if p.health == nil {
		log.Warning("No healthchecker")
		return
	}

	p.probe.Do(func() error {
		for {
			err := p.health.Check(p)
			if err != nil {
				// Check already recorded the failure (and any state change) on
				// the breaker. Keep probing with exponential backoff.
				return err
			}

			// Check recorded a success and advanced the recovery state.
			switch p.breaker.State() {
			case StateClosed:
				// Fully recovered: stop this probe round.
				return nil
			case StateHalfOpen:
				// Recovering: keep probing at the steady base interval rather
				// than the grown failure backoff, so a healthy upstream returns
				// to full rotation promptly. A failed check above reopens it.
				if !p.probe.Wait(p.probe.Interval()) {
					return nil
				}
			default:
				// Transient state (e.g. breaking disabled mid-probe): stop.
				return nil
			}
		}
	})
}

// StartFailed marks the proxy down until its first successful health check and
// starts probing immediately. Start must be called first to set the probe interval.
func (p *Proxy) StartFailed() {
	p.breaker.MarkOpen()
	p.Healthcheck()
}

// Down reports whether the proxy must not receive traffic: it is either fully
// open (removed after consecutive failures, or awaiting its first startup
// check) or in half-open state and not admitting this call. A zero maxfails
// disables the check entirely, preserving the legacy behavior.
func (p *Proxy) Down(maxfails uint32) bool {
	if maxfails == 0 {
		return false
	}
	return !p.breaker.Admit()
}

// Stop stops health checking and closes the DoQ transport, when configured.
func (p *Proxy) Stop() {
	p.probe.Stop()
	if p.doq != nil {
		p.doq.stopTransport()
	}
}

func (p *Proxy) finalizer() {
	if p.doq != nil {
		p.doq.stopTransport()
		return
	}
	p.transport.Stop()
}

// Start starts the proxy's healthchecking.
func (p *Proxy) Start(duration time.Duration) {
	p.probe.Start(duration)
	if p.doq != nil {
		p.doq.start()
		return
	}
	p.transport.Start()
}

// SetHealthBackoff caps the exponential wait between consecutive failed
// health checks.
func (p *Proxy) SetHealthBackoff(maxBackoff time.Duration) {
	p.probe.SetMaxBackoff(maxBackoff)
}

func (p *Proxy) SetReadTimeout(duration time.Duration) {
	p.readTimeout = duration
	if p.doq != nil {
		p.doq.setReadTimeout(duration)
	}
}

// SetLocalAddress sets the local address for the proxy, used as the source address for outbound connections.
func (p *Proxy) SetLocalAddress(addr net.IP) {
	p.transport.SetLocalAddress(addr)
	if p.doq != nil {
		p.doq.setLocalAddress(addr)
	}
	if p.transport.httpClient != nil {
		httpTransport := p.transport.httpClient.Transport.(*http.Transport)
		if addr == nil {
			httpTransport.DialContext = nil
			return
		}
		dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: addr}}
		httpTransport.DialContext = dialer.DialContext
	}
}

const (
	maxTimeout = 2 * time.Second
)
