// Package up is used to run a function for some duration. If a new function is added while a previous run is
// still ongoing, nothing new will be executed.
package up

import (
	"sync"
	"time"
)

// Probe is used to run a single Func until it returns true (indicating a target is healthy). If an Func
// is already in progress no new one will be added, i.e. there is always a maximum of 1 checks in flight.
//
// There is a tradeoff to be made in figuring out quickly that an upstream is healthy and not doing much work
// (sending queries) to find that out. When a check keeps failing the wait between checks backs off
// exponentially from interval up to maxBackoff, so a persistently broken upstream is not probed
// indefinitely at the full rate. A successful check resets the backoff. In the end, with the default
// interval, the first check after a failure still happens quickly, which strikes a balance between getting
// information about the upstream state quickly and not doing too much work.
type Probe struct {
	sync.Mutex
	inprogress int
	interval   time.Duration
	maxBackoff time.Duration
	backoff    time.Duration
	stop       chan struct{}
	stopped    bool
}

// Func is used to determine if a target is alive. If so this function must return nil.
type Func func() error

// New returns a pointer to an initialized Probe.
func New() *Probe { return &Probe{maxBackoff: defaultMaxBackoff} }

// Do will probe target, if a probe is already in progress this is a noop.
func (p *Probe) Do(f Func) {
	p.Lock()
	if p.inprogress != idle {
		p.Unlock()
		return
	}
	p.inprogress = active
	interval := p.interval
	// A previous round may have left a grown backoff; a fresh round starts at interval.
	p.backoff = 0
	p.Unlock()
	// Passed the lock. Now run f for as long it returns false. If a true is returned
	// we return from the goroutine and we can accept another Func to run.
	go func() {
		for {
			if err := f(); err == nil {
				break
			}
			if !p.wait(interval) {
				return
			}
			interval = p.nextInterval(interval)
		}

		p.Lock()
		p.inprogress = idle
		p.backoff = 0
		p.Unlock()
	}()
}

// wait sleeps for d and reports whether the Probe is still meant to run afterwards.
func (p *Probe) wait(d time.Duration) bool {
	if d <= 0 {
		d = intervalFloor
	}
	t := time.NewTimer(d)
	defer t.Stop()
	p.Lock()
	stop := p.stop
	p.Unlock()
	if stop == nil {
		<-t.C
		return true
	}
	select {
	case <-t.C:
		return true
	case <-stop:
		return false
	}
}

// Wait sleeps for d or until the Probe is stopped. It reports whether the
// Probe is still running afterwards. It lets a probe Func pace itself during
// recovery without blocking shutdown.
func (p *Probe) Wait(d time.Duration) bool {
	return p.wait(d)
}

// Interval returns the configured base probe interval.
func (p *Probe) Interval() time.Duration {
	p.Lock()
	defer p.Unlock()
	return p.interval
}

// nextInterval doubles the current wait, capped at maxBackoff.
func (p *Probe) nextInterval(cur time.Duration) time.Duration {
	p.Lock()
	defer p.Unlock()
	next := cur * 2
	max := p.maxBackoff
	if max <= 0 {
		max = defaultMaxBackoff
	}
	if next > max || next <= 0 {
		next = max
	}
	p.backoff = next
	return next
}

// Stop stops the probing. It is safe to call multiple times.
func (p *Probe) Stop() {
	p.Lock()
	if p.stopped {
		p.Unlock()
		return
	}
	p.stopped = true
	if p.stop == nil {
		p.stop = make(chan struct{})
	}
	close(p.stop)
	p.inprogress = stop
	p.Unlock()
}

// Start will initialize the probe manager, after which probes can be initiated with Do.
func (p *Probe) Start(interval time.Duration) {
	p.Lock()
	p.interval = interval
	if p.stop == nil {
		p.stop = make(chan struct{})
	}
	p.Unlock()
}

// SetMaxBackoff caps the exponential wait between consecutive failed checks. A non-positive
// value restores the default cap.
func (p *Probe) SetMaxBackoff(d time.Duration) {
	p.Lock()
	p.maxBackoff = d
	p.Unlock()
}

const (
	idle = iota
	active
	stop

	intervalFloor     = 10 * time.Millisecond
	defaultMaxBackoff = 30 * time.Second
)
