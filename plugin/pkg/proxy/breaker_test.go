package proxy

import (
	"testing"
	"time"
)

func TestBreakerDisabledAlwaysAdmits(t *testing.T) {
	b := NewBreaker(0)
	for range 10 {
		b.RecordFailure()
	}
	if !b.Admit() {
		t.Error("breaker with maxFails 0 must always admit traffic")
	}
	if b.State() != StateClosed {
		t.Errorf("expected closed state, got %s", b.State())
	}
}

func TestBreakerOpensAfterConsecutiveFailures(t *testing.T) {
	var transitions []State
	b := NewBreaker(3)
	b.onTransition = func(s State) { transitions = append(transitions, s) }

	b.ObserveRequest()
	b.ObserveFailure()
	b.RecordFailure()
	if b.State() != StateClosed {
		t.Fatalf("expected closed after 1 failure, got %s", b.State())
	}
	b.RecordFailure()
	b.RecordFailure()

	if b.State() != StateOpen {
		t.Fatalf("expected open after 3 consecutive failures, got %s", b.State())
	}
	if b.Admit() {
		t.Error("open breaker must not admit traffic")
	}
	if len(transitions) != 1 || transitions[0] != StateOpen {
		t.Errorf("expected one transition to open, got %v", transitions)
	}
}

func TestBreakerSuccessResetsConsecutiveFailures(t *testing.T) {
	b := NewBreaker(3)
	b.RecordFailure()
	b.RecordFailure()
	b.RecordSuccess(5 * time.Millisecond)
	b.RecordFailure()
	b.RecordFailure()

	if b.State() != StateClosed {
		t.Errorf("expected closed after success reset the streak, got %s", b.State())
	}
}

func TestBreakerHalfOpenGradualThenClose(t *testing.T) {
	b := NewBreaker(1)
	b.SetHalfOpenWeight(10)

	// Open it.
	b.RecordFailure()
	if b.State() != StateOpen {
		t.Fatalf("expected open, got %s", b.State())
	}

	// A successful probe promotes to half-open.
	b.RecordSuccess(time.Millisecond)
	if b.State() != StateHalfOpen {
		t.Fatalf("expected half-open after successful probe, got %s", b.State())
	}

	// Weight gates traffic: with weight 10, roughly one in ten calls is admitted.
	admitted := 0
	for range 100 {
		if b.Admit() {
			admitted++
		}
	}
	if admitted != 10 {
		t.Errorf("expected 10 admitted trials out of 100 at 10%% weight, got %d", admitted)
	}

	// Enough consecutive successful trials close the breaker.
	for range defaultHalfOpenTrials {
		b.RecordSuccess(time.Millisecond)
	}
	if b.State() != StateClosed {
		t.Fatalf("expected closed after %d trials, got %s", defaultHalfOpenTrials, b.State())
	}
	if !b.Admit() {
		t.Error("closed breaker must admit all traffic")
	}
}

func TestBreakerHalfOpenFailureReopens(t *testing.T) {
	b := NewBreaker(1)
	b.RecordFailure()
	b.RecordSuccess(time.Millisecond) // -> half-open
	if b.State() != StateHalfOpen {
		t.Fatalf("expected half-open, got %s", b.State())
	}

	b.RecordFailure()
	if b.State() != StateOpen {
		t.Fatalf("expected reopen after failed trial, got %s", b.State())
	}
}

func TestBreakerMarkOpen(t *testing.T) {
	b := NewBreaker(2)
	b.MarkOpen()
	if b.State() != StateOpen {
		t.Fatalf("expected open, got %s", b.State())
	}
	if b.Admit() {
		t.Error("an open breaker must not admit traffic")
	}

	// MarkOpen on an already-open breaker is a no-op, and a disabled breaker ignores it.
	b.MarkOpen()
	if b.State() != StateOpen {
		t.Fatalf("expected still open, got %s", b.State())
	}
	b2 := NewBreaker(0)
	b2.MarkOpen()
	if b2.State() != StateClosed {
		t.Fatalf("disabled breaker must stay closed, got %s", b2.State())
	}
}

func TestBreakerFailureRateAndLatency(t *testing.T) {
	b := NewBreaker(100)
	if got := b.FailureRate(); got != 0 {
		t.Errorf("expected zero failure rate without samples, got %f", got)
	}

	for range 4 {
		b.ObserveRequest()
	}
	b.ObserveFailure()
	b.ObserveFailure()

	if got := b.FailureRate(); got != 0.5 {
		t.Errorf("expected failure rate 0.5, got %f", got)
	}
	if b.Requests() != 4 || b.Failures() != 2 {
		t.Errorf("unexpected counters: requests=%d failures=%d", b.Requests(), b.Failures())
	}

	b.RecordSuccess(10 * time.Millisecond)
	b.RecordSuccess(20 * time.Millisecond)
	lat := b.AvgLatency()
	if lat <= 0 || lat > 20*time.Millisecond {
		t.Errorf("expected smoothed latency in (0,20ms], got %s", lat)
	}
}

func TestBreakerHalfOpenWeightClamped(t *testing.T) {
	b := NewBreaker(1)
	b.SetHalfOpenWeight(250)
	b.RecordFailure()
	b.RecordSuccess(time.Millisecond)
	if !b.Admit() {
		t.Error("weight above 100 must be clamped to full admission")
	}

	b2 := NewBreaker(1)
	b2.SetHalfOpenWeight(0)
	b2.RecordFailure()
	b2.RecordSuccess(time.Millisecond)
	if b2.Admit() {
		t.Error("weight 0 must admit no traffic while half-open")
	}
}
