package up

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestUp(t *testing.T) {
	pr := New()
	wg := sync.WaitGroup{}
	hits := int32(0)

	upfunc := func() error {
		atomic.AddInt32(&hits, 1)
		// Sleep tiny amount so that our other pr.Do() calls hit the lock.
		time.Sleep(3 * time.Millisecond)
		wg.Done()
		return nil
	}

	pr.Start(5 * time.Millisecond)
	defer pr.Stop()

	// These functions AddInt32 to the same hits variable, but we only want to wait when
	// upfunc finishes, as that only calls Done() on the waitgroup.
	upfuncNoWg := func() error { atomic.AddInt32(&hits, 1); return nil }
	wg.Add(1)
	pr.Do(upfunc)
	pr.Do(upfuncNoWg)
	pr.Do(upfuncNoWg)

	wg.Wait()

	h := atomic.LoadInt32(&hits)
	if h != 1 {
		t.Errorf("Expected hits to be %d, got %d", 1, h)
	}
}

func TestUpBackoff(t *testing.T) {
	pr := New()
	pr.Start(20 * time.Millisecond)
	pr.SetMaxBackoff(160 * time.Millisecond)
	defer pr.Stop()

	var attempts int32
	release := make(chan struct{})
	pr.Do(func() error {
		n := atomic.AddInt32(&attempts, 1)
		if n >= 4 {
			close(release)
			return nil
		}
		return errFailed
	})

	select {
	case <-release:
	case <-time.After(2 * time.Second):
		t.Fatalf("probe did not finish backoff cycle, attempts=%d", atomic.LoadInt32(&attempts))
	}

	if got := atomic.LoadInt32(&attempts); got != 4 {
		t.Fatalf("Expected 4 attempts, got %d", got)
	}

	// A successful run resets the backoff; a new failing round must start from interval again.
	stamps := make(chan time.Time, 4)
	var secondAttempts int32
	second := make(chan struct{})
	pr.Do(func() error {
		n := atomic.AddInt32(&secondAttempts, 1)
		stamps <- time.Now()
		if n >= 3 {
			close(second)
			return nil
		}
		return errFailed
	})

	select {
	case <-second:
	case <-time.After(2 * time.Second):
		t.Fatal("second probe round did not finish")
	}
	close(stamps)
	ts := make([]time.Time, 0, 3)
	for stamp := range stamps {
		ts = append(ts, stamp)
	}
	if len(ts) != 3 {
		t.Fatalf("expected 3 timestamps, got %d", len(ts))
	}
	// First gap of the new round must be the base interval, not a grown backoff.
	gap := ts[1].Sub(ts[0])
	if gap > 20*time.Millisecond+15*time.Millisecond {
		t.Errorf("backoff was not reset after success: first gap %s", gap)
	}
}

func TestUpStopDuringWait(t *testing.T) {
	pr := New()
	pr.Start(50 * time.Millisecond)

	var attempts int32
	pr.Do(func() error {
		atomic.AddInt32(&attempts, 1)
		return errFailed
	})

	time.Sleep(20 * time.Millisecond)
	pr.Stop()

	// After Stop, no further attempt may land; give the timer room to fire if it were still running.
	time.Sleep(80 * time.Millisecond)
	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Errorf("Expected no further attempts after Stop, got %d", got)
	}
}

var errFailed = &probeErr{"probe failed"}

type probeErr struct{ msg string }

func (e *probeErr) Error() string { return e.msg }
