package health

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	ctest "github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func newUID618Monitor(t *testing.T, cfg OverloadConfig) *OverloadMonitor {
	t.Helper()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("invalid test config: %v", err)
	}
	return NewOverloadMonitor(cfg)
}

func TestUID618OverloadMonitorInflightHysteresis(t *testing.T) {
	m := newUID618Monitor(t, OverloadConfig{MaxInflight: 10, RecoveryInflight: 5})

	if s := m.Evaluate(); s.Overloaded {
		t.Fatalf("expected healthy initially, got %+v", s)
	}

	m.SetInFlight(10) // threshold is crossed only above 10.
	if s := m.Evaluate(); s.Overloaded {
		t.Fatalf("value equal to high watermark should not overload: %+v", s)
	}

	m.SetInFlight(11)
	s := m.Evaluate()
	if !s.Overloaded || s.Reason != ReasonInflight {
		t.Fatalf("expected inflight overload, got %+v", s)
	}
	if !strings.Contains(s.Message, "inflight=11") {
		t.Fatalf("message should contain current value, got %q", s.Message)
	}

	m.SetInFlight(7)
	s = m.Evaluate()
	if !s.Overloaded {
		t.Fatalf("expected hysteresis to keep overloaded at 7 (>5): %+v", s)
	}
	if s.Reason != ReasonInflight || !strings.Contains(s.Message, "hysteresis") {
		t.Fatalf("expected hysteresis reason, got %+v", s)
	}

	m.SetInFlight(5)
	s = m.Evaluate()
	if s.Overloaded || s.Reason != "ok" {
		t.Fatalf("expected recovery at low watermark, got %+v", s)
	}
}

func TestUID618OverloadMonitorQueueAndLatency(t *testing.T) {
	m := newUID618Monitor(t, OverloadConfig{
		MaxQueueDepth:      10,
		RecoveryQueueDepth: 5,
		MaxLatency:         100 * time.Millisecond,
		RecoveryLatency:    50 * time.Millisecond,
	})

	m.SetQueueDepth(11)
	m.RecordLatency(101 * time.Millisecond)
	s := m.Evaluate()
	if !s.Overloaded {
		t.Fatalf("expected queue/latency overload: %+v", s)
	}
	if len(s.Reasons) != 2 {
		t.Fatalf("expected two reasons, got %v", s.Reasons)
	}

	// Both signals must enter their hysteresis bands before recovery.
	m.SetQueueDepth(7)
	m.RecordLatency(75 * time.Millisecond)
	if s := m.Evaluate(); !s.Overloaded {
		t.Fatalf("expected hysteresis retention: %+v", s)
	}

	m.SetQueueDepth(5)
	m.RecordLatency(40 * time.Millisecond)
	if s := m.Evaluate(); s.Overloaded {
		t.Fatalf("expected recovery after both low watermarks: %+v", s)
	}
}

func TestUID618OverloadMonitorDefaultRatio(t *testing.T) {
	m := NewOverloadMonitor(OverloadConfig{MaxInflight: 100, MaxQueueDepth: 200, MaxLatency: time.Second})
	if m.cfg.RecoveryInflight != 80 || m.cfg.RecoveryQueueDepth != 160 || m.cfg.RecoveryLatency != 800*time.Millisecond {
		t.Fatalf("unexpected normalized recovery thresholds: %+v", m.cfg)
	}
}

func TestUID618HealthEndpointOverloadReasonAndCompatibility(t *testing.T) {
	m := newUID618Monitor(t, OverloadConfig{MaxInflight: 10, RecoveryInflight: 5})
	h := &health{monitor: m}

	get := func() *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		h.serveHealth(rr, req)
		return rr
	}

	rr := get()
	if rr.Code != http.StatusOK || rr.Body.String() != "OK" {
		t.Fatalf("healthy probe = %d %q, want 200 OK", rr.Code, rr.Body.String())
	}

	m.SetInFlight(11)
	rr = get()
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("overloaded probe status = %d, want 503", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "overloaded") || !strings.Contains(body, ReasonInflight) {
		t.Fatalf("overloaded body should explain reason, got %q", body)
	}
	if got := rr.Header().Get("X-CoreDNS-Health-Reason"); got != ReasonInflight {
		t.Fatalf("reason header = %q, want %q", got, ReasonInflight)
	}

	m.SetInFlight(7)
	if rr = get(); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("hysteresis should retain 503, got %d", rr.Code)
	}

	m.SetInFlight(5)
	rr = get()
	if rr.Code != http.StatusOK || rr.Body.String() != "OK" {
		t.Fatalf("recovered probe = %d %q, want exact OK", rr.Code, rr.Body.String())
	}
}

func TestUID618HealthStateEndpointJSON(t *testing.T) {
	m := newUID618Monitor(t, OverloadConfig{MaxQueueDepth: 1, RecoveryQueueDepth: 0})
	m.SetQueueDepth(2)
	h := &health{monitor: m}

	rr := httptest.NewRecorder()
	h.serveState(rr, httptest.NewRequest(http.MethodGet, "/health/state", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("state status = %d, want 503", rr.Code)
	}
	var got Snapshot
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("state endpoint returned invalid JSON %q: %v", rr.Body.String(), err)
	}
	if !got.Overloaded || got.QueueDepth != 2 || got.Reason != ReasonQueue {
		t.Fatalf("unexpected JSON snapshot: %+v", got)
	}
}

type uid618BlockingPlugin struct {
	started chan struct{}
	release chan struct{}
}

func (p *uid618BlockingPlugin) Name() string { return "uid618-blocking-plugin" }
func (p *uid618BlockingPlugin) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	close(p.started)
	select {
	case <-p.release:
	case <-ctx.Done():
		return dns.RcodeServerFailure, ctx.Err()
	}
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Rcode = dns.RcodeNameError
	_ = w.WriteMsg(msg)
	return dns.RcodeNameError, nil
}

func TestUID618HealthMiddlewareTracksInflightAndMetrics(t *testing.T) {
	m := NewOverloadMonitor(OverloadConfig{})
	p := &uid618BlockingPlugin{started: make(chan struct{}), release: make(chan struct{})}
	h := &health{monitor: m, Next: p}

	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)
	rw := dnstest.NewRecorder(&ctest.ResponseWriter{})

	done := make(chan error, 1)
	go func() {
		_, err := h.ServeDNS(context.Background(), rw, req)
		done <- err
	}()

	select {
	case <-p.started:
	case <-time.After(5 * time.Second):
		t.Fatal("plugin did not start")
	}
	if got := m.InFlight(); got != 1 {
		t.Fatalf("inflight while next plugin runs = %d, want 1", got)
	}

	close(p.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServeDNS returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeDNS did not finish")
	}
	if got := m.InFlight(); got != 0 {
		t.Fatalf("inflight after request = %d, want 0", got)
	}
	if m.Latency() <= 0 {
		// Evaluate flushes the sample into Latency.
		m.Evaluate()
	}
	if m.Latency() <= 0 {
		t.Fatal("expected latency sample to be recorded")
	}

	counter := RequestTotal.WithLabelValues(p.Name(), "NXDOMAIN")
	if got := testutil.ToFloat64(counter); got < 1 {
		t.Fatalf("plugin/rcode counter = %v, want at least 1", got)
	}
	if rw.Rcode != dns.RcodeNameError {
		t.Fatalf("recorder rcode = %d, want NXDOMAIN", rw.Rcode)
	}
}

type uid618NamedHandler struct {
	name  string
	next  plugin.Handler
	write bool
	rcode int
}

func (h *uid618NamedHandler) Name() string { return h.name }
func (h *uid618NamedHandler) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if h.next != nil {
		return plugin.NextOrFailure(h.name, h.next, ctx, w, r)
	}
	if h.write {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Rcode = h.rcode
		if err := w.WriteMsg(msg); err != nil {
			return dns.RcodeServerFailure, err
		}
	}
	return h.rcode, nil
}

func TestUID618HealthMiddlewareTracksActualPluginThroughNestedChain(t *testing.T) {
	terminal := &uid618NamedHandler{name: "uid618-terminal-plugin", write: true, rcode: dns.RcodeRefused}
	middle := &uid618NamedHandler{name: "uid618-middle-plugin", next: terminal, rcode: dns.RcodeRefused}
	h := &health{monitor: NewOverloadMonitor(OverloadConfig{}), Next: middle}

	req := new(dns.Msg)
	req.SetQuestion("nested.example.", dns.TypeA)
	rw := dnstest.NewRecorder(&ctest.ResponseWriter{})
	if _, err := h.ServeDNS(context.Background(), rw, req); err != nil {
		t.Fatalf("ServeDNS failed: %v", err)
	}
	if rw.Rcode != dns.RcodeRefused {
		t.Fatalf("recorder rcode = %d, want REFUSED", rw.Rcode)
	}
	if got := testutil.ToFloat64(RequestTotal.WithLabelValues(terminal.name, "REFUSED")); got < 1 {
		t.Fatalf("terminal plugin/refused counter = %v, want >= 1", got)
	}
	if got := testutil.ToFloat64(RequestTotal.WithLabelValues(middle.name, "REFUSED")); got != 0 {
		t.Fatalf("middle plugin should not be labeled as writer, counter = %v", got)
	}
}

func TestUID618SchedulerQueueDepthSource(t *testing.T) {
	if got := SchedulerQueueDepth(); got < 0 {
		t.Fatalf("scheduler queue depth = %d, want non-negative", got)
	}
	m := NewOverloadMonitor(OverloadConfig{MaxQueueDepth: 1, QueueSource: "runtime"})
	if m.sig.queueFn == nil {
		t.Fatal("runtime queue source was not installed")
	}
	if s := m.Evaluate(); s.QueueDepth < 0 {
		t.Fatalf("evaluated queue depth = %d", s.QueueDepth)
	}
}

func TestUID618ParseHealthOverloadOptions(t *testing.T) {
	tests := []struct {
		name  string
		input string
		check func(*testing.T, *health)
	}{
		{
			name: "flat options",
			input: `health 127.0.0.1:0 {
				lameduck 250ms
				inflight_threshold 100
				queue_threshold 50
				latency_threshold 25ms
				recovery_ratio 0.5
			}`,
			check: func(t *testing.T, h *health) {
				if h.Addr != "127.0.0.1:0" || h.lameduck != 250*time.Millisecond {
					t.Fatalf("unexpected base config: %+v", h)
				}
				cfg := h.monitor.cfg
				if cfg.MaxInflight != 100 || cfg.MaxQueueDepth != 50 || cfg.MaxLatency != 25*time.Millisecond {
					t.Fatalf("thresholds not parsed: %+v", cfg)
				}
				if cfg.RecoveryInflight != 50 || cfg.RecoveryQueueDepth != 25 || cfg.RecoveryLatency != 25*time.Millisecond/2 {
					t.Fatalf("ratio recovery thresholds wrong: %+v", cfg)
				}
			},
		},
		{
			name: "nested block and explicit recovery",
			input: `health {
				overload {
					inflight 10
					queue 8
					latency 1s
					recovery_inflight 4
					recovery_queue 2
					recovery_latency 200ms
				}
			}`,
			check: func(t *testing.T, h *health) {
				cfg := h.monitor.cfg
				if cfg.MaxInflight != 10 || cfg.MaxQueueDepth != 8 || cfg.MaxLatency != time.Second {
					t.Fatalf("nested thresholds not parsed: %+v", cfg)
				}
				if cfg.RecoveryInflight != 4 || cfg.RecoveryQueueDepth != 2 || cfg.RecoveryLatency != 200*time.Millisecond {
					t.Fatalf("explicit recovery thresholds not parsed: %+v", cfg)
				}
			},
		},
		{
			name: "positional overload and percent hysteresis",
			input: `health {
				overload 1000 2000 3s
				hysteresis 80%
			}`,
			check: func(t *testing.T, h *health) {
				cfg := h.monitor.cfg
				if cfg.MaxInflight != 1000 || cfg.MaxQueueDepth != 2000 || cfg.MaxLatency != 3*time.Second {
					t.Fatalf("positional thresholds not parsed: %+v", cfg)
				}
				if cfg.RecoveryRatio != 0.8 {
					t.Fatalf("recovery ratio = %v, want 0.8", cfg.RecoveryRatio)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, err := parseHealth(caddy.NewTestController("dns", tc.input))
			if err != nil {
				t.Fatalf("parseHealth failed: %v", err)
			}
			if tc.check != nil {
				tc.check(t, h)
			}
		})
	}
}

func TestUID618ParseHealthOverloadErrors(t *testing.T) {
	inputs := []string{
		`health { inflight_threshold -1 }`,
		`health { inflight_threshold nope }`,
		`health { latency_threshold soon }`,
		`health { recovery_ratio 1.5 }`,
		`health { inflight_threshold 10; recovery_inflight 11 }`,
		`health { overload { unknown_option 1 } }`,
	}
	for _, input := range inputs {
		if _, err := parseHealth(caddy.NewTestController("dns", input)); err == nil {
			t.Fatalf("expected error for %q", input)
		}
	}
}

func TestUID618SetupHealthRegistersMiddleware(t *testing.T) {
	c := caddy.NewTestController("dns", `health 127.0.0.1:0 {
		inflight_threshold 10
	}`)
	if err := setup(c); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
}

func TestUID618OverloadMonitorConcurrent(t *testing.T) {
	m := NewOverloadMonitor(OverloadConfig{MaxInflight: 100000})
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				m.IncInFlight()
				m.RecordLatency(time.Microsecond)
				m.DecInFlight()
				m.Evaluate()
			}
		}()
	}
	wg.Wait()
	if got := m.InFlight(); got != 0 {
		t.Fatalf("inflight = %d, want 0", got)
	}
}

func TestUID618HealthLameduckKeepsOK(t *testing.T) {
	h := &health{monitor: NewOverloadMonitor(OverloadConfig{MaxInflight: 1})}
	h.monitor.SetInFlight(10)
	h.lameducking.Store(true)
	rr := httptest.NewRecorder()
	h.serveHealth(rr, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("lameduck probe status = %d, want 200", rr.Code)
	}
	if body, _ := io.ReadAll(rr.Result().Body); string(body) != "OK" {
		t.Fatalf("lameduck body = %q, want OK", body)
	}
}

var _ plugin.Handler = (*health)(nil)
