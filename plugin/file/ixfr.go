package file

import (
	"fmt"

	"github.com/miekg/dns"
)

type ixfrPhase int

const (
	ixfrDelete ixfrPhase = iota
	ixfrAdd
)

// ixfrState implements the RFC 1995 SOA boundary state machine. The response
// can either be a real delta sequence or an AXFR-style full zone.
type ixfrState struct {
	origin string
	delta  *Zone
	full   *Zone

	leading *dns.SOA
	phase   ixfrPhase

	// expectDeleteSOA is true when the next SOA is either the older SOA that
	// begins a deletion group or the trailing/current SOA.
	expectDeleteSOA bool
	ixfrStarted     bool
	axfr            bool
	complete        bool
	preSOARecord    bool
}

func newIXFRState(current *Zone) *ixfrState {
	return &ixfrState{
		origin:          current.origin,
		delta:           current.Clone(),
		phase:           ixfrDelete,
		expectDeleteSOA: true,
	}
}

func (s *ixfrState) handle(rr dns.RR) error {
	if rr == nil {
		return nil
	}
	soa, isSOA := rr.(*dns.SOA)

	if s.leading == nil {
		if !isSOA {
			return fmt.Errorf("IXFR response did not begin with SOA, got %s", dns.TypeToString[rr.Header().Rrtype])
		}
		s.leading = soa
		s.full = NewZone(s.origin, "")
		if err := s.full.Insert(dns.Copy(soa)); err != nil {
			return err
		}
		return nil
	}

	if s.axfr {
		return s.full.Insert(rr)
	}

	// Before the second SOA establishes the response shape, keep a full-zone
	// candidate in case this is AXFR-style IXFR.
	if !s.ixfrStarted {
		if err := s.full.Insert(rr); err != nil {
			return err
		}
	}

	if isSOA {
		if s.expectDeleteSOA {
			switch {
			case soa.Serial == s.leading.Serial && !s.ixfrStarted:
				// SOA(new), complete zone, SOA(new). The second SOA is the
				// trailing marker and there is no further useful data.
				s.axfr = true
				s.complete = true
				return nil
			case soa.Serial == s.leading.Serial && s.ixfrStarted:
				// Trailing SOA after the final addition group.
				s.complete = true
				return nil
			default:
				// Older/intermediate SOA that starts a deletion group.
				// RFC 1995 puts this SOA immediately after the leading SOA.
				if s.preSOARecord && !s.ixfrStarted {
					return fmt.Errorf("IXFR has ordinary records before its deletion SOA")
				}
				s.ixfrStarted = true
				s.phase = ixfrDelete
				s.expectDeleteSOA = false
				s.full = nil // The response is now known to be incremental.
				return nil
			}
		}

		// SOA that starts the corresponding addition group.
		if err := s.delta.Insert(dns.Copy(soa)); err != nil {
			return err
		}
		s.phase = ixfrAdd
		s.expectDeleteSOA = true
		return nil
	}

	if !s.ixfrStarted {
		// Until the second SOA identifies the shape, ordinary records belong
		// to a possible AXFR-style response. Do not apply them as deletions:
		// a full-zone record will often be absent from the old candidate.
		s.preSOARecord = true
		return nil
	}

	switch s.phase {
	case ixfrDelete:
		return s.delta.DeleteRR(rr)
	case ixfrAdd:
		return s.delta.Insert(rr)
	default:
		return fmt.Errorf("invalid IXFR processing phase")
	}
}

func (s *ixfrState) result() *Zone {
	if s.axfr {
		return s.full
	}
	return s.delta
}
