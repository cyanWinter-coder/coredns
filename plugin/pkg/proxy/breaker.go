package proxy

import (
	"sync"
	"sync/atomic"
	"time"
)

// State is the circuit-breaker state of one upstream.
type State uint32

const (
	// StateClosed forwards all traffic to the upstream.
	StateClosed State = iota
	// StateOpen drops traffic without contacting the upstream; probes keep checking it.
	StateOpen
	// StateHalfOpen admits only a fraction of traffic as trials while the upstream proves itself.
	StateHalfOpen
)

func (s State) String() string {
	switch s {
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half_open"
	default:
		return "closed"
	}
}

// Default breaker parameters.
const (
	// defaultHalfOpenWeight is the share of traffic, in percent, admitted to a half-open upstream.
	defaultHalfOpenWeight uint32 = 10
	// defaultHalfOpenTrials is the number of consecutive successful probes needed to close again.
	defaultHalfOpenTrials uint32 = 3
	// ewmaWeight smooths the per-upstream latency average.
	ewmaWeight int64 = 8
)

// Breaker tracks the health of a single upstream and decides whether traffic
// may reach it. It is safe for concurrent use.
//
// State transitions are driven by forwarded exchanges and the owning Proxy's
// health probes:
//
//	Closed   -- maxConsecutiveFails consecutive failures --> Open
//	Open     -- a successful probe                       --> HalfOpen
//	HalfOpen -- halfOpenTrials consecutive successful probes --> Closed
//	HalfOpen -- one failed probe or trial                --> Open
type Breaker struct {
	// Configuration.
	maxConsecutiveFails uint32
	halfOpenWeight      uint32 // percent of traffic admitted while half-open
	halfOpenTrials      uint32 // consecutive successes required to close

	state atomic.Uint32

	// consecutive failures observed on forwarded traffic and probes.
	consecutiveFails atomic.Uint32

	mu sync.Mutex // guards halfOpenTrial and state transitions

	// halfOpenTrial counts consecutive successful probes in half-open state.
	halfOpenTrial uint32

	// request statistics, all atomic.
	requests        atomic.Uint64
	failures        atomic.Uint64
	avgLatencyNanos atomic.Int64
	// trialCounter gates half-open traffic without perturbing the request counters.
	trialCounter atomic.Uint64

	// onTransition is invoked after every breaker state change.
	onTransition func(State)
}

// NewBreaker returns a breaker that opens after maxFails consecutive failures.
// A zero maxFails disables breaking: the upstream is always admitted.
func NewBreaker(maxFails uint32) *Breaker {
	b := &Breaker{
		maxConsecutiveFails: maxFails,
		halfOpenWeight:      defaultHalfOpenWeight,
		halfOpenTrials:      defaultHalfOpenTrials,
	}
	b.state.Store(uint32(StateClosed))
	return b
}

// SetHalfOpenWeight configures the percentage (0-100) of traffic admitted while
// half-open. Values above 100 are clamped to 100.
func (b *Breaker) SetHalfOpenWeight(percent uint32) {
	if percent > 100 {
		percent = 100
	}
	b.halfOpenWeight = percent
}

// State returns the current breaker state.
func (b *Breaker) State() State { return State(b.state.Load()) }

// disabled reports whether breaking is turned off (max_fails 0).
func (b *Breaker) disabled() bool { return b.maxConsecutiveFails == 0 }

// Admit reports whether a request may be sent to this upstream right now.
// Closed upstreams are always admitted; open upstreams are never admitted;
// half-open upstreams admit a fixed share of traffic as trials.
func (b *Breaker) Admit() bool {
	if b.disabled() {
		return true
	}
	switch b.State() {
	case StateClosed:
		return true
	case StateOpen:
		return false
	default: // half-open
		w := b.halfOpenWeight
		if w == 0 {
			return false
		}
		if w >= 100 {
			return true
		}
		return b.trialCounter.Add(1)%100 < uint64(w)
	}
}

// RecordSuccess accounts for a successful forwarded exchange or health probe,
// advancing the open -> half-open -> closed recovery sequence as appropriate.
func (b *Breaker) RecordSuccess(latency time.Duration) {
	b.consecutiveFails.Store(0)
	b.recordLatency(latency)

	if b.disabled() {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.State() {
	case StateOpen:
		// First successful probe promotes to half-open recovery.
		b.halfOpenTrial = 1
		b.transition(StateHalfOpen)
	case StateHalfOpen:
		b.halfOpenTrial++
		if b.halfOpenTrial >= b.halfOpenTrials {
			b.halfOpenTrial = 0
			b.transition(StateClosed)
		}
	}
}

// RecordFailure accounts for a failed forwarded exchange or probe and returns
// the new consecutive-failure count.
func (b *Breaker) RecordFailure() uint32 {
	fails := b.consecutiveFails.Add(1)
	if b.disabled() {
		return fails
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.State() {
	case StateHalfOpen:
		// A failed trial removes the upstream immediately; the probe restarts backoff.
		b.halfOpenTrial = 0
		b.transition(StateOpen)
	case StateClosed:
		if fails >= b.maxConsecutiveFails {
			b.transition(StateOpen)
		}
	}
	return fails
}

// MarkOpen forces the breaker into the open state. It is used for upstreams
// that must not receive traffic before their first successful check
// (the start_failed option).
func (b *Breaker) MarkOpen() {
	if b.disabled() {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.halfOpenTrial = 0
	b.transition(StateOpen)
}

// transition updates the state and runs the state-change hook. Caller holds b.mu.
func (b *Breaker) transition(s State) {
	if b.State() == s {
		return
	}
	b.state.Store(uint32(s))
	if b.onTransition != nil {
		b.onTransition(s)
	}
}

// ObserveRequest increments the total request counter.
func (b *Breaker) ObserveRequest() { b.requests.Add(1) }

// ObserveFailure increments the failed request counter.
func (b *Breaker) ObserveFailure() { b.failures.Add(1) }

func (b *Breaker) recordLatency(d time.Duration) {
	if d <= 0 {
		return
	}
	cur := b.avgLatencyNanos.Load()
	if cur == 0 {
		b.avgLatencyNanos.Store(int64(d))
		return
	}
	b.avgLatencyNanos.Store(cur + (int64(d)-cur)/ewmaWeight)
}

// Requests returns the total number of forwarded exchanges observed.
func (b *Breaker) Requests() uint64 { return b.requests.Load() }

// Failures returns the total number of failed forwarded exchanges observed.
func (b *Breaker) Failures() uint64 { return b.failures.Load() }

// FailureRate returns the share of observed exchanges that failed, 0 when no
// exchange has been observed yet.
func (b *Breaker) FailureRate() float64 {
	reqs := b.requests.Load()
	if reqs == 0 {
		return 0
	}
	return float64(b.failures.Load()) / float64(reqs)
}

// AvgLatency returns the smoothed per-upstream exchange latency.
func (b *Breaker) AvgLatency() time.Duration {
	return time.Duration(b.avgLatencyNanos.Load())
}

// ConsecutiveFails returns the current consecutive failure count.
func (b *Breaker) ConsecutiveFails() uint32 { return b.consecutiveFails.Load() }
