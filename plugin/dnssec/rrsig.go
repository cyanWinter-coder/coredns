package dnssec

import (
	"github.com/miekg/dns"
)

// servfailMsg returns a SERVFAIL reply for req, with the same question so clients can
// match it to their query.
func servfailMsg(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	if req != nil {
		m.SetRcode(req, dns.RcodeServerFailure)
	} else {
		m.Rcode = dns.RcodeServerFailure
		m.Response = true
	}
	return m
}

// questionName returns the qname for logging without panicking on malformed messages.
func questionName(m *dns.Msg) string {
	if m == nil || len(m.Question) == 0 {
		return "."
	}
	return m.Question[0].Name
}

// newRRSIG returns a new RRSIG, with all fields filled out, except the signed data.
func (k *DNSKEY) newRRSIG(signerName string, ttl, incep, expir uint32) *dns.RRSIG {
	sig := new(dns.RRSIG)

	sig.Hdr.Rrtype = dns.TypeRRSIG
	sig.Algorithm = k.K.Algorithm
	sig.KeyTag = k.tag
	sig.SignerName = signerName
	sig.Hdr.Ttl = ttl
	sig.OrigTtl = origTTL

	sig.Inception = incep
	sig.Expiration = expir

	return sig
}

// signRRSet signs rrs and returns the RRSIG. When wildcard is not empty, rrs was
// synthesized from that wildcard owner for the name it currently carries. The
// signature is then computed over the wildcard owner, so the RRSIG's Labels field is
// smaller than the owner's label count, as RFC 4034 section 3.1.3 requires. The
// RRSIG owner name itself stays the synthesized name.
func (k *DNSKEY) signRRSet(rrs []dns.RR, signerName string, ttl, incep, expir uint32, wildcard string) (*dns.RRSIG, error) {
	if wildcard == "" {
		sig := k.newRRSIG(signerName, ttl, incep, expir)
		if err := sig.Sign(k.s, rrs); err != nil {
			return nil, err
		}
		return sig, nil
	}

	owner := rrs[0].Header().Name
	copied := make([]dns.RR, len(rrs))
	for i := range rrs {
		copied[i] = dns.Copy(rrs[i])
		copied[i].Header().Name = wildcard
	}

	sig := k.newRRSIG(signerName, ttl, incep, expir)
	if err := sig.Sign(k.s, copied); err != nil {
		return nil, err
	}
	// Sign derives the RRSIG owner from the RRset; for a wildcard expansion the
	// RRSIG must be served under the queried name.
	sig.Hdr.Name = owner
	return sig, nil
}

type rrset struct {
	qname string
	qtype uint16
}

// rrSets returns rrs as a map of RRsets. It skips RRSIG and OPT records as those don't need to be signed.
func rrSets(rrs []dns.RR) map[rrset][]dns.RR {
	m := make(map[rrset][]dns.RR)

	for _, r := range rrs {
		if r.Header().Rrtype == dns.TypeRRSIG || r.Header().Rrtype == dns.TypeOPT {
			continue
		}

		if s, ok := m[rrset{r.Header().Name, r.Header().Rrtype}]; ok {
			s = append(s, r)
			m[rrset{r.Header().Name, r.Header().Rrtype}] = s
			continue
		}

		s := make([]dns.RR, 1, 3)
		s[0] = r
		m[rrset{r.Header().Name, r.Header().Rrtype}] = s
	}

	if len(m) > 0 {
		return m
	}
	return nil
}

const origTTL = 3600
