package dnssec

import (
	"crypto"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/pkg/cache"
	"github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

func TestSignWildcardLabels(t *testing.T) {
	d, rm1, rm2 := newDnssec(t, []string{"miek.nl."})
	defer rm1()
	defer rm2()

	m := &dns.Msg{
		Question: []dns.Question{{Name: "a.miek.nl.", Qclass: dns.ClassINET, Qtype: dns.TypeA}},
		Answer:   []dns.RR{test.A("a.miek.nl.	1800	IN	A	139.162.196.78")},
	}
	state := request.Request{Req: m, Zone: "miek.nl."}

	signed, err := d.signMessage(state, time.Now().UTC(), server, "*.miek.nl.")
	if err != nil {
		t.Fatal(err)
	}

	var sig *dns.RRSIG
	for _, rr := range signed.Answer {
		if s, ok := rr.(*dns.RRSIG); ok {
			sig = s
		}
	}
	if sig == nil {
		t.Fatal("Expected an RRSIG in the answer")
	}
	// RFC 4034 3.1.3: the Labels field counts the labels of the wildcard owner
	// without the "*", while the RRSIG itself is served under the queried name.
	if want := uint8(dns.CountLabel("miek.nl.")); sig.Labels != want {
		t.Errorf("Expected RRSIG labels %d, got %d", want, sig.Labels)
	}
	if sig.Hdr.Name != "a.miek.nl." {
		t.Errorf("Expected RRSIG owner a.miek.nl., got %s", sig.Hdr.Name)
	}
	if err := sig.Verify(d.keys[0].K, []dns.RR{test.A("a.miek.nl.	1800	IN	A	139.162.196.78")}); err != nil {
		t.Errorf("Signature over the wildcard expansion does not verify: %s", err)
	}
}

func TestSignWildcardOnlyExpansion(t *testing.T) {
	d, rm1, rm2 := newDnssec(t, []string{"miek.nl."})
	defer rm1()
	defer rm2()

	// The wildcard metadata only applies to the RRset whose owner is the queried
	// name; glue or CNAME targets in the same response must be signed as-is.
	m := &dns.Msg{
		Question: []dns.Question{{Name: "a.miek.nl.", Qclass: dns.ClassINET, Qtype: dns.TypeA}},
		Answer: []dns.RR{
			test.A("a.miek.nl.	1800	IN	A	139.162.196.78"),
			test.A("ns.a.miek.nl.	1800	IN	A	139.162.196.79"),
		},
	}
	state := request.Request{Req: m, Zone: "miek.nl."}
	signed, err := d.signMessage(state, time.Now().UTC(), server, "*.miek.nl.")
	if err != nil {
		t.Fatal(err)
	}

	for _, rr := range signed.Answer {
		sig, ok := rr.(*dns.RRSIG)
		if !ok || sig.TypeCovered != dns.TypeA {
			continue
		}
		switch sig.Hdr.Name {
		case "a.miek.nl.":
			if sig.Labels != uint8(dns.CountLabel("miek.nl.")) {
				t.Errorf("Wildcard expansion should have %d labels, got %d", dns.CountLabel("miek.nl."), sig.Labels)
			}
		case "ns.a.miek.nl.":
			if sig.Labels != uint8(dns.CountLabel("ns.a.miek.nl.")) {
				t.Errorf("Literal name should have %d labels, got %d", dns.CountLabel("ns.a.miek.nl."), sig.Labels)
			}
		}
	}
}

func TestSignCacheKeyIncludesKeyTags(t *testing.T) {
	k1, rm1, rm2 := newKey(t)
	defer rm1()
	defer rm2()

	fPriv, rmPriv, _ := test.TempFile(".", privKey1)
	fPub, rmPub, _ := test.TempFile(".", pubKey1)
	defer rmPriv()
	defer rmPub()
	k2, err := ParseKeyFile(fPub, fPriv)
	if err != nil {
		t.Fatal(err)
	}

	m := testMsg()
	state := request.Request{Req: m, Zone: "miek.nl."}

	// Sign with only the first key set.
	ca := cache.New[[]dns.RR](defaultCap)
	one := New([]string{"miek.nl."}, []*DNSKEY{k1}, false, nil, ca)
	if _, err := one.signMessage(state, time.Now().UTC(), server, ""); err != nil {
		t.Fatal(err)
	}

	// A second instance that has both keys configured (the rollover window) must not
	// find the single-key cache entry; it has to sign with both keys.
	two := New([]string{"miek.nl."}, []*DNSKEY{k1, k2}, false, nil, ca)
	sigs, err := two.sign(m.Answer, "miek.nl.", 1703, 0, 0, server)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 2 {
		t.Fatalf("Expected signatures from both keys, got %d", len(sigs))
	}

	// And a single-key instance must not pick up the both-key signatures.
	single := New([]string{"miek.nl."}, []*DNSKEY{k1}, false, nil, ca)
	if sigs, ok := single.get(hash(testMsg().Answer), server, "miek.nl.", ""); ok && len(sigs) != 1 {
		t.Errorf("Single-key instance reused %d signatures from a two-key cache", len(sigs))
	}
}

func TestSignOldKeyStillServedDuringRollover(t *testing.T) {
	k1, rm1, rm2 := newKey(t)
	defer rm1()
	defer rm2()

	fPriv, rmPriv, _ := test.TempFile(".", privKey1)
	fPub, rmPub, _ := test.TempFile(".", pubKey1)
	defer rmPriv()
	defer rmPub()
	k2, err := ParseKeyFile(fPub, fPriv)
	if err != nil {
		t.Fatal(err)
	}

	m := testMsg()
	state := request.Request{Req: m, Zone: "miek.nl."}
	ca := cache.New[[]dns.RR](defaultCap)
	d := New([]string{"miek.nl."}, []*DNSKEY{k1, k2}, false, nil, ca)
	if _, err := d.signMessage(state, time.Now().UTC(), server, ""); err != nil {
		t.Fatal(err)
	}

	// While both keys are configured, both signatures are served from the cache.
	// The hash is taken from a pristine RRset, not from the one signing mutated.
	sigs, ok := d.get(hash(testMsg().Answer), server, "miek.nl.", "")
	if !ok {
		t.Fatal("Expected a cache hit")
	}
	if len(sigs) != 2 {
		t.Fatalf("Expected 2 cached signatures during rollover, got %d", len(sigs))
	}
}

func TestSignSERVFAILWithoutKeys(t *testing.T) {
	ca := cache.New[[]dns.RR](defaultCap)
	d := New([]string{"miek.nl."}, []*DNSKEY{}, false, nil, ca)

	m := testMsg()
	state := request.Request{Req: m, Zone: "miek.nl."}
	resp := d.Sign(state, time.Now().UTC(), server)
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("Expected SERVFAIL without keys, got %s", dns.RcodeToString[resp.Rcode])
	}
}

func TestSignSERVFAILUnsupportedAlgorithm(t *testing.T) {
	k, rm1, rm2 := newKey(t)
	defer rm1()
	defer rm2()

	// Use a key whose public algorithm has no supported signing implementation.
	bad := &DNSKEY{
		K: &dns.DNSKEY{
			Hdr:       dns.RR_Header{Name: "miek.nl.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
			Flags:     257,
			Protocol:  3,
			Algorithm: dns.RSAMD5,
			PublicKey: "AwEAAcFpDv+Cb23kFJowu+VU++b2N1uEHi6Ll9H0BzLasFOdJjEEclCO",
		},
		s:   k.s,
		tag: k.tag,
	}

	ca := cache.New[[]dns.RR](defaultCap)
	d := New([]string{"miek.nl."}, []*DNSKEY{bad}, false, nil, ca)

	m := testMsg()
	state := request.Request{Req: m, Zone: "miek.nl."}
	resp := d.Sign(state, time.Now().UTC(), server)
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("Expected SERVFAIL for unsupported algorithm, got %s", dns.RcodeToString[resp.Rcode])
	}
}

func TestSignSERVFAILSplitKeysOnlyKSK(t *testing.T) {
	// A KSK-only split-key configuration cannot sign ordinary RRSets. Serving them
	// unsigned would be insecure, so the reply must be a SERVFAIL.
	k, rm1, rm2 := newKey(t)
	defer rm1()
	defer rm2()

	ca := cache.New[[]dns.RR](defaultCap)
	d := New([]string{"miek.nl."}, []*DNSKEY{k}, true, nil, ca)

	m := &dns.Msg{
		Question: []dns.Question{{Name: "miek.nl.", Qclass: dns.ClassINET, Qtype: dns.TypeMX}},
		Answer:   []dns.RR{test.MX("miek.nl.	1800	IN	MX	1 aspmx.l.google.com.")},
	}
	state := request.Request{Req: m, Zone: "miek.nl."}
	resp := d.Sign(state, time.Now().UTC(), server)
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("Expected SERVFAIL when no key may sign the RRset, got %s", dns.RcodeToString[resp.Rcode])
	}
}

// flakySigner succeeds allow times and fails afterwards. It simulates a key that
// works for some records but not others (or fails mid-way through a response).
type flakySigner struct {
	inner crypto.Signer
	allow int
	calls int
}

func (f *flakySigner) Public() crypto.PublicKey { return f.inner.Public() }
func (f *flakySigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	f.calls++
	if f.calls > f.allow {
		return nil, io.ErrUnexpectedEOF
	}
	return f.inner.Sign(rand, digest, opts)
}

func TestSignNegativeRcodeNotRewrittenOnNSECFailure(t *testing.T) {
	k, rm1, rm2 := newKey(t)
	defer rm1()
	defer rm2()

	// The first signature (the SOA) succeeds, signing the NSEC proof fails.
	flaky := &DNSKEY{
		K:   dns.Copy(k.K).(*dns.DNSKEY),
		s:   &flakySigner{inner: k.s, allow: 1},
		tag: k.tag,
	}

	ca := cache.New[[]dns.RR](defaultCap)
	d := New([]string{"miek.nl."}, []*DNSKEY{flaky}, false, nil, ca)

	m := testNxdomainMsg()
	state := request.Request{Req: m, Zone: "miek.nl."}
	signed, err := d.signMessage(state, time.Now().UTC(), server, "")
	if err == nil {
		t.Fatal("Expected an error when the NSEC proof cannot be signed")
	}
	// The NXDOMAIN must not have been turned into a NOERROR reply without proof.
	if signed.Rcode != dns.RcodeNameError {
		t.Errorf("Expected rcode to stay NXDOMAIN, got %s", dns.RcodeToString[signed.Rcode])
	}
}

func TestSignNSECQueryKeepsAllSignatures(t *testing.T) {
	// Two keys, an NSEC query: the denial of existence proof in the answer must
	// keep the signatures of both keys.
	k1, rm1, rm2 := newKey(t)
	defer rm1()
	defer rm2()

	fPriv, rmPriv, _ := test.TempFile(".", privKey1)
	fPub, rmPub, _ := test.TempFile(".", pubKey1)
	defer rmPriv()
	defer rmPub()
	k2, err := ParseKeyFile(fPub, fPriv)
	if err != nil {
		t.Fatal(err)
	}

	ca := cache.New[[]dns.RR](defaultCap)
	d := New([]string{"miek.nl."}, []*DNSKEY{k1, k2}, false, nil, ca)

	m := testNsecMsg()
	m.SetQuestion("www.miek.nl.", dns.TypeNSEC)
	state := request.Request{Req: m, Zone: "miek.nl."}
	signed, err := d.signMessage(state, time.Now().UTC(), server, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(signed.Ns) != 0 {
		t.Errorf("Authority section should be empty, got %d RRs", len(signed.Ns))
	}
	var nsecs, sigs int
	for _, rr := range signed.Answer {
		switch rr.(type) {
		case *dns.NSEC:
			nsecs++
		case *dns.RRSIG:
			sigs++
		}
	}
	if nsecs != 1 || sigs != 2 {
		t.Errorf("Expected 1 NSEC and 2 RRSIGs in the answer, got %d and %d", nsecs, sigs)
	}
}

func TestSignCacheTTL(t *testing.T) {
	d, rm1, rm2 := newDnssec(t, []string{"miek.nl."})
	defer rm1()
	defer rm2()

	m := testMsg()
	state := request.Request{Req: m, Zone: "miek.nl."}
	if _, err := d.signMessage(state, time.Now().UTC(), server, ""); err != nil {
		t.Fatal(err)
	}

	base := hash(testMsg().Answer)
	key := d.cacheKey(base, "")
	if _, ok := d.get(base, server, "miek.nl.", ""); !ok {
		t.Fatal("Expected a cache hit right after signing")
	}

	// Push the entry past its TTL: it must no longer be served.
	d.meta.Add(key, cacheMeta{signer: "miek.nl.", expire: time.Now().UTC().Add(-time.Second)})
	if _, ok := d.get(base, server, "miek.nl.", ""); ok {
		t.Error("Expected cache miss for an entry whose TTL has passed")
	}
}

func TestCacheMetaRemovedOldKey(t *testing.T) {
	// A cached signature from a key that is no longer configured must not be
	// served, even if the RRset content is unchanged.
	k1, rm1, rm2 := newKey(t)
	defer rm1()
	defer rm2()

	m := testMsg()
	state := request.Request{Req: m, Zone: "miek.nl."}
	ca := cache.New[[]dns.RR](defaultCap)
	d := New([]string{"miek.nl."}, []*DNSKEY{k1}, false, nil, ca)
	if _, err := d.signMessage(state, time.Now().UTC(), server, ""); err != nil {
		t.Fatal(err)
	}

	// Simulate a cache entry whose signature was made by a key that is gone.
	k2 := *k1
	k2.tag = k1.tag + 1
	d2 := New([]string{"miek.nl."}, []*DNSKEY{&k2}, false, nil, ca)
	if _, ok := d2.get(hash(m.Answer), server, "miek.nl.", ""); ok {
		t.Error("Expected no cache hit for signatures from a removed key")
	}
}

func TestWildcardFor(t *testing.T) {
	a := []dns.RR{test.A("a.miek.nl.	1800	IN	A	139.162.196.78")}
	if got := wildcardFor("*.miek.nl.", a, "a.miek.nl."); got != "*.miek.nl." {
		t.Errorf("Expected wildcard to apply, got %q", got)
	}
	// Other names in the same response are not the wildcard expansion.
	if got := wildcardFor("*.miek.nl.", a, "b.miek.nl."); got != "" {
		t.Errorf("Expected no wildcard for a different qname, got %q", got)
	}
	// A literal owner is signed as-is.
	if got := wildcardFor("", a, "a.miek.nl."); got != "" {
		t.Errorf("Expected no wildcard without metadata, got %q", got)
	}
}

func TestConfiguredTagsStable(t *testing.T) {
	d, rm1, rm2 := newDnssec(t, []string{"miek.nl."})
	defer rm1()
	defer rm2()

	first := d.configuredTags()
	second := d.configuredTags()
	if first != second {
		t.Errorf("configuredTags is not stable: %q != %q", first, second)
	}
	if strings.Contains(first, " ") {
		t.Errorf("configuredTags should not contain spaces: %q", first)
	}
}
