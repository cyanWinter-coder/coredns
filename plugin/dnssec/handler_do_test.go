package dnssec

import (
	"context"
	"testing"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/cache"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

// handlerFor returns a Dnssec plugin whose next handler writes the given answer for
// any query, so ServeDNS has something to sign.
func handlerFor(t *testing.T, answer []dns.RR, keys []*DNSKEY) Dnssec {
	t.Helper()
	next := plugin.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.Answer = answer
		w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	})
	return New([]string{"miek.nl."}, keys, false, next, cache.New[[]dns.RR](defaultCap))
}

func TestServeDNSDoZeroNeverSigns(t *testing.T) {
	k, rm1, rm2 := newKey(t)
	defer rm1()
	defer rm2()

	answer := []dns.RR{test.A("a.miek.nl.	1800	IN	A	139.162.196.78")}
	d := handlerFor(t, answer, []*DNSKEY{k})

	q := new(dns.Msg)
	q.SetQuestion("a.miek.nl.", dns.TypeA) // no DO bit

	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	if _, err := d.ServeDNS(context.TODO(), rec, q); err != nil {
		t.Fatal(err)
	}
	if got := countSigs(rec.Msg.Answer); got != 0 {
		t.Errorf("DO=0 reply must not carry RRSIGs, got %d", got)
	}
}

func TestServeDNSDoOneSigns(t *testing.T) {
	k, rm1, rm2 := newKey(t)
	defer rm1()
	defer rm2()

	answer := []dns.RR{test.A("a.miek.nl.	1800	IN	A	139.162.196.78")}
	d := handlerFor(t, answer, []*DNSKEY{k})

	q := new(dns.Msg)
	q.SetQuestion("a.miek.nl.", dns.TypeA)
	q.SetEdns0(4096, true) // DO bit

	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	if _, err := d.ServeDNS(context.TODO(), rec, q); err != nil {
		t.Fatal(err)
	}
	if got := countSigs(rec.Msg.Answer); got != 1 {
		t.Errorf("DO=1 reply must carry one RRSIG, got %d", got)
	}
}

func TestServeDNSSignFailureIsServfail(t *testing.T) {
	// A key whose signing always fails must produce a SERVFAIL, not an unsigned reply.
	k, rm1, rm2 := newKey(t)
	defer rm1()
	defer rm2()
	broken := &DNSKEY{
		K:   dns.Copy(k.K).(*dns.DNSKEY),
		s:   &errSigner{pub: k.s.Public()},
		tag: k.tag,
	}

	answer := []dns.RR{test.A("a.miek.nl.	1800	IN A	139.162.196.78")}
	d := handlerFor(t, answer, []*DNSKEY{broken})

	q := new(dns.Msg)
	q.SetQuestion("a.miek.nl.", dns.TypeA)
	q.SetEdns0(4096, true)

	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	rcode, err := d.ServeDNS(context.TODO(), rec, q)
	if err != nil {
		t.Fatal(err)
	}
	// The SERVFAIL has already been written, so ServeDNS reports success to stop
	// the server from writing a second reply (plugin.ClientWrite semantics).
	if rcode != dns.RcodeSuccess {
		t.Errorf("Expected the already-written reply to report success, got %d", rcode)
	}
	if rec.Msg.Rcode != dns.RcodeServerFailure {
		t.Errorf("Expected SERVFAIL message, got %s", dns.RcodeToString[rec.Msg.Rcode])
	}
	if countSigs(rec.Msg.Answer) != 0 {
		t.Error("SERVFAIL must not carry partial signatures")
	}
}

func countSigs(rrs []dns.RR) int {
	n := 0
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			n++
		}
	}
	return n
}
