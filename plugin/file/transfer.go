package file

import (
	"errors"
	"fmt"
	"time"

	"github.com/coredns/coredns/plugin/file/tree"
	"github.com/coredns/coredns/plugin/transfer"

	"github.com/miekg/dns"
)

var errIXFRFallback = errors.New("ixfr unavailable or malformed")

type transferResult struct {
	zone      *Zone
	stage     *zoneStage
	unchanged bool
}

// SyncIfNeeded checks the primary SOA serial and transfers the zone only when
// the primary has a newer serial. A genuine IXFR is tried first and any IXFR
// protocol or application error falls back to AXFR. The returned changed value
// reports whether a new generation was installed.
func (z *Zone) SyncIfNeeded(t *transfer.Transfer) (changed bool, err error) {
	z.transferMu.Lock()
	defer z.transferMu.Unlock()

	start := time.Now()
	ok, err := z.shouldTransfer()
	if err != nil {
		log.Errorf("Failed SOA serial check for zone %q: %v", z.origin, err)
		recordTransfer(z.origin, "soa", "failure")
		return false, err
	}
	if !ok {
		log.Infof("Skipping transfer for zone %q: SOA serial %d is current", z.origin, z.SOASerialIfDefined())
		recordTransfer(z.origin, "soa", "unchanged")
		zoneTransferDuration.WithLabelValues(z.origin, "soa", "unchanged").Observe(time.Since(start).Seconds())
		return false, nil
	}

	if err := z.transferInLocked(t, nil); err != nil {
		return false, err
	}
	return true, nil
}

// SyncOnce is an alias for SyncIfNeeded.
func (z *Zone) SyncOnce(t *transfer.Transfer) (bool, error) {
	return z.SyncIfNeeded(t)
}

func (z *Zone) TransferInWithRecords(t *transfer.Transfer, validate func([]dns.RR) error) error {
	z.transferMu.Lock()
	defer z.transferMu.Unlock()
	return z.transferInLocked(t, validate)
}

func (z *Zone) transferInLocked(t *transfer.Transfer, validate func([]dns.RR) error) error {
	if len(z.TransferFrom) == 0 {
		return nil
	}

	var lastErr error
	for _, master := range z.TransferFrom {
		if z.getSOA() != nil {
			start := time.Now()
			res, err := z.transferIXFR(master, validate)
			if err == nil {
				return z.installTransfer(res, t, master, "ixfr", start)
			}
			lastErr = err
			log.Warningf("IXFR failed for zone %q from %q, falling back to AXFR: %v", z.origin, master, err)
			recordTransfer(z.origin, "ixfr", "fallback")
		}

		start := time.Now()
		res, err := z.transferAXFR(master, validate)
		if err == nil {
			return z.installTransfer(res, t, master, "axfr", start)
		}
		lastErr = err
		log.Errorf("Failed to transfer zone %q from %q: %v", z.origin, master, err)
	}

	recordTransfer(z.origin, "transfer", "failure")
	if lastErr == nil {
		lastErr = fmt.Errorf("no transfer servers succeeded for %s", z.origin)
	}
	return lastErr
}

func (z *Zone) installTransfer(res *transferResult, t *transfer.Transfer, master, protocol string, start time.Time) error {
	if res == nil {
		return fmt.Errorf("%s transfer returned empty result for %s", protocol, z.origin)
	}
	if res.unchanged {
		recordTransfer(z.origin, protocol, "unchanged")
		zoneTransferDuration.WithLabelValues(z.origin, protocol, "unchanged").Observe(time.Since(start).Seconds())
		log.Infof("Zone %q is already at primary SOA serial", z.origin)
		z.notifySecondaries(t)
		return nil
	}
	if res.zone == nil || res.stage == nil {
		return fmt.Errorf("%s transfer for %s produced no staged zone", protocol, z.origin)
	}

	if err := res.stage.Commit(); err != nil {
		res.stage.Abort()
		recordTransfer(z.origin, protocol, "failure")
		zoneTransferDuration.WithLabelValues(z.origin, protocol, "failure").Observe(time.Since(start).Seconds())
		log.Errorf("Failed to atomically install staged zone %q from %q: %v", z.origin, master, err)
		return fmt.Errorf("commit zone %s: %w", z.origin, err)
	}

	z.setData(res.zone.Apex, res.zone.Tree)
	recordTransfer(z.origin, protocol, "success")
	zoneTransferDuration.WithLabelValues(z.origin, protocol, "success").Observe(time.Since(start).Seconds())
	log.Infof("Transferred zone %q from %s using %s with SOA serial %d", z.origin, master, protocol, res.zone.SOA.Serial)

	z.notifySecondaries(t)
	return nil
}

func (z *Zone) notifySecondaries(t *transfer.Transfer) {
	if t == nil {
		return
	}
	if err := t.Notify(z.origin); err != nil {
		log.Warningf("Failed sending notify for zone %q: %v", z.origin, err)
		recordNotify(z.origin, "out", "failure")
		return
	}
	recordNotify(z.origin, "out", "success")
}

func (z *Zone) transferAXFR(master string, validate func([]dns.RR) error) (*transferResult, error) {
	m := new(dns.Msg)
	m.SetAxfr(z.origin)

	client := new(dns.Transfer)
	ch, err := client.In(m, master)
	if err != nil {
		recordTransfer(z.origin, "axfr", "failure")
		log.Errorf("Failed to set up AXFR for zone %q with %q: %v", z.origin, master, err)
		return nil, err
	}

	stage, err := newZoneStage(z.File())
	if err != nil {
		return nil, fmt.Errorf("create staging file for %s: %w", z.origin, err)
	}
	success := false
	defer func() {
		if !success {
			stage.Abort()
		}
	}()

	if _, err := stage.WriteString("$ORIGIN " + z.origin + "\n"); err != nil {
		return nil, err
	}

	var (
		records  []dns.RR
		xfrErr   error
		writeErr error
		received int
	)
	for env := range ch {
		if env.Error != nil {
			xfrErr = env.Error
			continue
		}
		for _, rr := range env.RR {
			received++
			if writeErr == nil {
				if _, err := stage.WriteString(rr.String() + "\n"); err != nil {
					writeErr = err
				}
			}
			if validate != nil {
				records = append(records, rr)
			}
		}
	}
	if xfrErr != nil {
		recordTransfer(z.origin, "axfr", "failure")
		log.Errorf("AXFR stream for zone %q from %q failed after %d RRs: %v", z.origin, master, received, xfrErr)
		return nil, xfrErr
	}
	if writeErr != nil {
		recordTransfer(z.origin, "axfr", "failure")
		return nil, fmt.Errorf("write AXFR staging file for %s: %w", z.origin, writeErr)
	}

	candidate, err := stage.Parse(z.origin)
	if err != nil {
		recordTransfer(z.origin, "axfr", "failure")
		log.Errorf("Failed to validate staged AXFR zone %q from %q: %v", z.origin, master, err)
		return nil, err
	}
	if validate != nil {
		if err := validate(records); err != nil {
			recordTransfer(z.origin, "axfr", "failure")
			log.Errorf("Post-transfer validation failed for zone %q from %q: %v", z.origin, master, err)
			return nil, err
		}
	}

	success = true
	return &transferResult{zone: candidate, stage: stage}, nil
}

func (z *Zone) transferIXFR(master string, validate func([]dns.RR) error) (*transferResult, error) {
	localSOA := z.getSOA()
	if localSOA == nil {
		return nil, errors.New("local SOA is required to request IXFR")
	}

	m := new(dns.Msg)
	m.SetIxfr(z.origin, localSOA.Serial, localSOA.Ns, localSOA.Mbox)
	ch, err := new(dns.Transfer).In(m, master)
	if err != nil {
		recordTransfer(z.origin, "ixfr", "failure")
		return nil, err
	}

	state := newIXFRState(z)
	var xfrErr error
	for env := range ch {
		if env.Error != nil {
			xfrErr = env.Error
			continue
		}
		for _, rr := range env.RR {
			if err := state.handle(rr); err != nil {
				xfrErr = err
			}
		}
	}
	if xfrErr != nil {
		recordTransfer(z.origin, "ixfr", "failure")
		return nil, fmt.Errorf("%w: %v", errIXFRFallback, xfrErr)
	}
	if state.leading == nil {
		recordTransfer(z.origin, "ixfr", "failure")
		return nil, fmt.Errorf("%w: empty IXFR response", errIXFRFallback)
	}
	if !state.ixfrStarted && !state.axfr {
		// A single current SOA means no delta. If its serial differs from the
		// local serial, ask for a complete AXFR rather than guessing.
		if state.leading.Serial == localSOA.Serial {
			return &transferResult{unchanged: true}, nil
		}
		return nil, fmt.Errorf("%w: single SOA serial %d does not match local %d", errIXFRFallback, state.leading.Serial, localSOA.Serial)
	}
	if state.ixfrStarted && !state.complete {
		return nil, fmt.Errorf("%w: truncated IXFR change sequence", errIXFRFallback)
	}
	if state.axfr && !state.complete {
		return nil, fmt.Errorf("%w: truncated AXFR-style IXFR response", errIXFRFallback)
	}

	candidate := state.result()
	if candidate == nil || candidate.SOA == nil {
		return nil, fmt.Errorf("%w: IXFR produced no SOA", errIXFRFallback)
	}

	stage, err := newZoneStage(z.File())
	if err != nil {
		return nil, fmt.Errorf("create IXFR staging file for %s: %w", z.origin, err)
	}
	success := false
	defer func() {
		if !success {
			stage.Abort()
		}
	}()
	if _, err := stage.WriteString("$ORIGIN " + z.origin + "\n"); err != nil {
		return nil, err
	}
	bw := stage.writer
	if err := writeZone(bw, candidate); err != nil {
		return nil, err
	}
	if err := stage.Validate(z.origin); err != nil {
		recordTransfer(z.origin, "ixfr", "failure")
		return nil, fmt.Errorf("%w: %v", errIXFRFallback, err)
	}
	if validate != nil {
		if err := validate(candidate.allRecords()); err != nil {
			recordTransfer(z.origin, "ixfr", "failure")
			return nil, err
		}
	}

	success = true
	return &transferResult{zone: candidate, stage: stage}, nil
}

func (z *Zone) allRecords() []dns.RR {
	ap, tr := z.snapshot()
	rrs, _ := ap.records()
	if tr != nil {
		_ = tr.Walk(func(e *tree.Elem, _ map[uint16][]dns.RR) error {
			rrs = append(rrs, e.All()...)
			return nil
		})
	}
	return rrs
}
