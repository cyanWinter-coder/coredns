package dnssec

import (
	"context"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/metadata"
	"github.com/coredns/coredns/plugin/pkg/cache"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

// TestResponseWriterUsesWildcardMetadata runs the response writer with the
// zone/wildcard metadata the *file* plugin sets, and checks that the RRSIG of the
// wildcard expansion is signed over the wildcard owner.
func TestResponseWriterUsesWildcardMetadata(t *testing.T) {
	k, rm1, rm2 := newKey(t)
	defer rm1()
	defer rm2()

	ctx := metadata.ContextWithMetadata(context.Background())
	metadata.SetValueFunc(ctx, "zone/wildcard", func() string { return "*.miek.nl." })

	d := New([]string{"miek.nl."}, []*DNSKEY{k}, false, nil, cache.New[[]dns.RR](defaultCap))
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	rw := &ResponseWriter{ResponseWriter: rec, d: d, server: server, ctx: ctx}

	res := new(dns.Msg)
	res.SetQuestion("a.miek.nl.", dns.TypeA)
	res.Response = true
	res.Answer = []dns.RR{test.A("a.miek.nl.	1800	IN	A	139.162.196.78")}

	if err := rw.WriteMsg(res); err != nil {
		t.Fatal(err)
	}
	if rec.Msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("Expected NOERROR, got %s", dns.RcodeToString[rec.Msg.Rcode])
	}

	var sig *dns.RRSIG
	for _, rr := range rec.Msg.Answer {
		if s, ok := rr.(*dns.RRSIG); ok && s.TypeCovered == dns.TypeA {
			sig = s
		}
	}
	if sig == nil {
		t.Fatal("Expected an RRSIG for the wildcard expansion")
	}
	if want := uint8(dns.CountLabel("miek.nl.")); sig.Labels != want {
		t.Errorf("Expected wildcard RRSIG with %d labels, got %d", want, sig.Labels)
	}
	if sig.Hdr.Name != "a.miek.nl." {
		t.Errorf("Expected RRSIG owner a.miek.nl., got %s", sig.Hdr.Name)
	}
	// The signature must verify when the verifier reconstructs the wildcard name.
	if err := sig.Verify(k.K, []dns.RR{test.A("a.miek.nl.	1800	IN	A	139.162.196.78")}); err != nil {
		t.Errorf("Wildcard RRSIG does not verify: %s", err)
	}
}

// TestResponseWriterNoMetadataSignsLiterally makes sure a response keeps working
// when the metadata plugin is not enabled (no zone/wildcard value).
func TestResponseWriterNoMetadataSignsLiterally(t *testing.T) {
	k, rm1, rm2 := newKey(t)
	defer rm1()
	defer rm2()

	d := New([]string{"miek.nl."}, []*DNSKEY{k}, false, nil, cache.New[[]dns.RR](defaultCap))
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	rw := &ResponseWriter{ResponseWriter: rec, d: d, server: server, ctx: context.Background()}

	res := new(dns.Msg)
	res.SetQuestion("a.miek.nl.", dns.TypeA)
	res.Response = true
	res.Answer = []dns.RR{test.A("a.miek.nl.	1800	IN	A	139.162.196.78")}

	if err := rw.WriteMsg(res); err != nil {
		t.Fatal(err)
	}
	if got := countSigs(rec.Msg.Answer); got != 1 {
		t.Errorf("Expected one RRSIG, got %d", got)
	}
}

// TestWildcardCacheKeyDiffers makes sure a wildcard expansion and a literal owner
// with the same synthesized content do not share cached signatures.
func TestWildcardCacheKeyDiffers(t *testing.T) {
	d, rm1, rm2 := newDnssec(t, []string{"miek.nl."})
	defer rm1()
	defer rm2()

	rrs := []dns.RR{test.A("a.miek.nl.	1800	IN	A	139.162.196.78")}
	literal := d.cacheKey(hash(rrs), "")
	wildcard := d.cacheKey(hash(rrs), "*.miek.nl.")
	if literal == wildcard {
		t.Error("Wildcard and literal RRsets must not share a cache key")
	}

	// And the cache keys differ across key sets as well.
	k2 := *d.keys[0]
	k2.tag++
	d2 := New([]string{"miek.nl."}, []*DNSKEY{&k2}, false, nil, d.cache)
	if got := d2.cacheKey(hash(rrs), ""); got == literal {
		t.Error("Cache key must change when the configured key set changes")
	}
}

func TestSignWildcardSignatureVerifies(t *testing.T) {
	d, rm1, rm2 := newDnssec(t, []string{"miek.nl."})
	defer rm1()
	defer rm2()

	rrs := []dns.RR{test.TXT(`a.miek.nl.	1800	IN	TXT	"response"`)}
	sig, err := d.keys[0].signRRSet(rrs, "miek.nl.", 1800, uint32(time.Now().Add(-3*time.Hour).Unix()), uint32(time.Now().Add(8*24*time.Hour).Unix()), "*.miek.nl.")
	if err != nil {
		t.Fatal(err)
	}
	if err := sig.Verify(d.keys[0].K, rrs); err != nil {
		t.Errorf("Wildcard signature does not verify: %s", err)
	}
	// Labels must be the owner labels minus the wildcard label.
	if want := uint8(dns.CountLabel("miek.nl.")); sig.Labels != want {
		t.Errorf("Expected %d labels, got %d", want, sig.Labels)
	}
}
