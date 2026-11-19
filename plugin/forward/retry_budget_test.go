package forward

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	proxyPkg "github.com/coredns/coredns/plugin/pkg/proxy"

	"github.com/miekg/dns"
)

// blackholeUDP starts a UDP listener that counts incoming packets but never
// responds, simulating an upstream that silently drops queries.
func blackholeUDP(t *testing.T) (addr string, packets *atomic.Int32) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start blackhole UDP listener: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	count := new(atomic.Int32)
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			count.Add(1)
		}
	}()
	return pc.LocalAddr().String(), count
}

// TestForwardContextDeadlineBoundsRetries verifies that a request context
// deadline tighter than the default 5s forwarding window caps the retry
// loop: ServeDNS must return shortly after the deadline instead of retrying
// upstreams for the full window. The cache plugin relies on this to bound
// background stale-verification refreshes (see serve_stale verify).
func TestForwardContextDeadlineBoundsRetries(t *testing.T) {
	addr, packets := blackholeUDP(t)

	f := New()
	f.maxfails = 0 // keep health checks out of the picture
	f.readTimeout = 100 * time.Millisecond
	// Uncapped connect attempts: only the time budget bounds the loop.
	f.maxConnectAttempts = 0
	f.maxConnectAttemptsSet = true
	p := proxyPkg.NewProxy("forward", addr, "dns")
	p.SetReadTimeout(f.readTimeout)
	f.SetProxy(p)
	defer p.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	start := time.Now()
	_, err := f.ServeDNS(ctx, &mockResponseWriter{}, req)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error from ServeDNS against a blackhole upstream")
	}
	// The retry loop must stop at the context deadline (plus at most one
	// in-flight read timeout), not run for the 5s default window.
	if elapsed > 2*time.Second {
		t.Fatalf("retry loop was not bounded by the context deadline: took %v", elapsed)
	}
	// Each attempt waits out one 100ms read timeout, so a 300ms window
	// allows a handful of packets, not the ~50 the 5s window would send.
	if got := packets.Load(); got > 10 {
		t.Fatalf("expected bounded upstream amplification, got %d packets", got)
	}
}

// TestForwardExpiredContextMakesNoAttempts verifies that an already expired
// request context short-circuits the retry loop without touching any
// upstream.
func TestForwardExpiredContextMakesNoAttempts(t *testing.T) {
	addr, packets := blackholeUDP(t)

	f := New()
	f.maxfails = 0
	p := proxyPkg.NewProxy("forward", addr, "dns")
	f.SetProxy(p)
	defer p.Stop()

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	if _, err := f.ServeDNS(ctx, &mockResponseWriter{}, req); err == nil {
		t.Fatal("expected error from ServeDNS with an expired context")
	}
	// Allow briefly for misdirected packets to arrive.
	time.Sleep(50 * time.Millisecond)
	if got := packets.Load(); got != 0 {
		t.Fatalf("expected no upstream packets with an expired context, got %d", got)
	}
}
