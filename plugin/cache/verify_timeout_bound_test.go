package cache

import (
	"context"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

// TestVerifyStaleTimeoutBoundsBackgroundRefresh verifies the trade-off
// between waiting on the upstream and serving an expired entry: once the
// verify timeout fires the client gets the stale answer, and the detached
// background refresh is canceled after one more timeout interval (2x
// VERIFY_TIMEOUT in total) so downstream retries — e.g. forward's — cannot
// amplify queries against an unresponsive upstream for their full retry
// window.
func TestVerifyStaleTimeoutBoundsBackgroundRefresh(t *testing.T) {
	const verifyTimeout = 50 * time.Millisecond

	c := New()
	c.staleUpTo = time.Hour
	c.verifyStale = true
	c.verifyStaleTimeout = verifyTimeout
	c.staleTTL = 30 * time.Second
	c.Next = ttlBackend(120)

	req := new(dns.Msg)
	req.SetQuestion("cached.org.", dns.TypeA)

	// Prime the cache, then move past the entry's TTL so it is stale.
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	if _, err := c.ServeDNS(context.Background(), rec, req.Copy()); err != nil {
		t.Fatalf("priming ServeDNS failed: %v", err)
	}
	if c.pcache.Len() != 1 {
		t.Fatal("expected primed cache entry")
	}
	c.now = func() time.Time { return time.Now().Add(3 * time.Minute) }

	// Swap in an upstream that never answers and reports when the refresh
	// context is canceled.
	canceled := make(chan time.Time, 1)
	c.Next = plugin.HandlerFunc(func(ctx context.Context, _ dns.ResponseWriter, _ *dns.Msg) (int, error) {
		<-ctx.Done()
		canceled <- time.Now()
		return dns.RcodeServerFailure, ctx.Err()
	})

	rec = dnstest.NewRecorder(&test.ResponseWriter{})
	start := time.Now()
	if _, err := c.ServeDNS(context.Background(), rec, req.Copy()); err != nil {
		t.Fatalf("stale ServeDNS failed: %v", err)
	}
	elapsed := time.Since(start)

	// The client must not wait for the dead upstream: it gets the stale
	// entry after roughly the verify timeout.
	if elapsed > 150*time.Millisecond {
		t.Fatalf("client was not served stale within the verify timeout: took %v", elapsed)
	}
	if rec.Msg == nil || len(rec.Msg.Answer) != 1 {
		t.Fatalf("expected the stale answer, got %+v", rec.Msg)
	}
	if got := rec.Msg.Answer[0].Header().Ttl; got != 30 {
		t.Fatalf("expected stale TTL=30, got %d", got)
	}

	// The background refresh keeps its grace window (one more timeout
	// interval) and is then canceled instead of running unbounded.
	select {
	case at := <-canceled:
		if d := at.Sub(start); d < 2*verifyTimeout {
			t.Fatalf("refresh canceled after %v, before its %v grace elapsed", d, 2*verifyTimeout)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("background refresh was not canceled; it would retry upstream unbounded")
	}
}

// TestCacheExpiryRefreshFailureServesStale verifies that when an entry has
// expired and the upstream keeps failing, the expired entry is served and
// concurrent requests share a single background refresh instead of each
// starting one (no request amplification).
func TestCacheExpiryRefreshFailureServesStale(t *testing.T) {
	const verifyTimeout = 50 * time.Millisecond

	c := New()
	c.staleUpTo = time.Hour
	c.verifyStale = true
	c.verifyStaleTimeout = verifyTimeout
	c.staleTTL = 30 * time.Second
	// Suppress further refresh attempts after a failed one, so the
	// assertion below does not depend on goroutine scheduling.
	c.staleRecheck = time.Minute
	c.Next = ttlBackend(120)

	req := new(dns.Msg)
	req.SetQuestion("cached.org.", dns.TypeA)

	// Prime the cache, then move past the entry's TTL so it is stale.
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	if _, err := c.ServeDNS(context.Background(), rec, req.Copy()); err != nil {
		t.Fatalf("priming ServeDNS failed: %v", err)
	}
	c.now = func() time.Time { return time.Now().Add(3 * time.Minute) }

	// Swap in an upstream that never answers.
	callsCh := make(chan struct{}, 16)
	c.Next = plugin.HandlerFunc(func(ctx context.Context, _ dns.ResponseWriter, _ *dns.Msg) (int, error) {
		callsCh <- struct{}{}
		<-ctx.Done()
		return dns.RcodeServerFailure, ctx.Err()
	})

	const queries = 3
	for range queries {
		rec = dnstest.NewRecorder(&test.ResponseWriter{})
		if _, err := c.ServeDNS(context.Background(), rec, req.Copy()); err != nil {
			t.Fatalf("stale ServeDNS failed: %v", err)
		}
		if rec.Msg == nil || len(rec.Msg.Answer) != 1 {
			t.Fatalf("expected the stale answer, got %+v", rec.Msg)
		}
	}

	// All queries above raced the same in-flight refresh: exactly one
	// upstream attempt must have started.
	got := len(callsCh)
	if got != 1 {
		t.Fatalf("expected 1 shared background refresh for %d stale queries, got %d", queries, got)
	}
}
