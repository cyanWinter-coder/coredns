// Package dnssec implements a plugin that signs responses on-the-fly using
// NSEC black lies.
package dnssec

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/cache"
	"github.com/coredns/coredns/plugin/pkg/response"
	"github.com/coredns/coredns/plugin/pkg/singleflight"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// Dnssec signs the reply on-the-fly.
type Dnssec struct {
	Next plugin.Handler

	zones     []string
	keys      []*DNSKEY
	splitkeys bool
	inflight  *singleflight.Group
	cache     *cache.Cache[[]dns.RR]

	// meta records, per signature cache key, the signer the signatures were made
	// for and when the entry's TTL runs out. Entries without matching meta are
	// treated as a cache miss, so the worst case is a re-sign.
	meta *cache.Cache[cacheMeta]
}

// cacheMeta describes the signatures cached under one cache key.
type cacheMeta struct {
	signer string // signer name (the zone that owns the name)
	expire time.Time
}

// New returns a new Dnssec.
func New(zones []string, keys []*DNSKEY, splitkeys bool, next plugin.Handler, c *cache.Cache[[]dns.RR]) Dnssec {
	return newWithMeta(zones, keys, splitkeys, next, c, cache.New[cacheMeta](defaultCap))
}

// newWithMeta is New with an explicit metadata cache. Sharing it with the periodic
// cleaner keeps the TTL bookkeeping in sync with the signature cache.
func newWithMeta(zones []string, keys []*DNSKEY, splitkeys bool, next plugin.Handler, c *cache.Cache[[]dns.RR], meta *cache.Cache[cacheMeta]) Dnssec {
	return Dnssec{Next: next,
		zones:     zones,
		keys:      keys,
		splitkeys: splitkeys,
		cache:     c,
		meta:      meta,
		inflight:  new(singleflight.Group),
	}
}

// Sign signs the message in state. It takes care of negative or nodata responses. It
// uses NSEC black lies for authenticated denial of existence. For delegations it
// will insert DS records and sign those.
// Signatures will be cached for a short while. By default we sign for 8 days,
// starting 3 hours ago.
//
// When a signature cannot be produced, for instance because no configured key
// applies to an RRset or because an algorithm is not supported, a SERVFAIL reply is
// returned (and the reason logged). Serving the RRset unsigned would be read as an
// insecure or bogus answer by a validating client, which is worse than failing the
// query.
func (d Dnssec) Sign(state request.Request, now time.Time, server string) *dns.Msg {
	m, err := d.signMessage(state, now, server, "")
	if err != nil {
		log.Errorf("Failed to sign reply for %q: %s", questionName(state.Req), err)
		return servfailMsg(state.Req)
	}
	return m
}

// signMessage signs the reply in state. wildcard is the owner name of the wildcard
// that synthesized the answer, if any (the *file* plugin records it as
// zone/wildcard metadata); it is needed to create RRSIGs with the correct Labels
// field. An error is returned when any required signature cannot be produced.
func (d Dnssec) signMessage(state request.Request, now time.Time, server, wildcard string) (*dns.Msg, error) {
	req := state.Req

	incep, expir := incepExpir(now)

	mt, _ := response.Typify(req, time.Now().UTC()) // TODO(miek): need opt record here?
	if mt == response.Delegation {
		if len(req.Ns) == 0 {
			return req, nil
		}
		// We either sign DS or NSEC of DS.
		ttl := req.Ns[0].Header().Ttl

		ds := []dns.RR{}
		for i := range req.Ns {
			if req.Ns[i].Header().Rrtype == dns.TypeDS {
				ds = append(ds, req.Ns[i])
			}
		}
		if len(ds) == 0 {
			sigs, err := d.nsec(state, mt, ttl, incep, expir, server)
			if err != nil {
				return req, err
			}
			req.Ns = append(req.Ns, sigs...)
		} else {
			sigs, err := d.sign(ds, state.Zone, ttl, incep, expir, server)
			if err != nil {
				return req, err
			}
			req.Ns = append(req.Ns, sigs...)
		}
		return req, nil
	}

	if mt == response.NameError || mt == response.NoData {
		if len(req.Ns) != 1 || req.Ns[0].Header().Rrtype != dns.TypeSOA {
			return req, nil
		}

		ttl := req.Ns[0].Header().Ttl

		// Build the denial of existence proof first. Without it there is no usable
		// negative answer and the rcode must not be rewritten: doing so would turn
		// an NXDOMAIN into an unsigned NOERROR reply.
		nsecRRs, err := d.nsec(state, mt, ttl, incep, expir, server)
		if err != nil {
			return req, err
		}

		if state.QType() == dns.TypeNSEC {
			// The qtype was NSEC: answer with the NSEC and all its signatures,
			// without the SOA.
			req.Answer = nsecRRs
			req.Ns = nil
			req.Rcode = dns.RcodeSuccess
			return req, nil
		}

		sigs, err := d.sign(req.Ns, state.Zone, ttl, incep, expir, server)
		if err != nil {
			return req, err
		}
		req.Ns = append(req.Ns, sigs...)
		req.Ns = append(req.Ns, nsecRRs...)
		req.Rcode = dns.RcodeSuccess
		return req, nil
	}

	zones := plugin.Zones(d.zones) // only sign if CNAME is not outside of our zones
	for _, r := range rrSets(req.Answer) {
		signer := zones.Matches(r[0].Header().Name)
		if signer == "" {
			continue
		}
		wc := wildcardFor(wildcard, r, state.QName())
		sigs, err := d.sign(r, signer, r[0].Header().Ttl, incep, expir, server, wc)
		if err != nil {
			return req, err
		}
		req.Answer = append(req.Answer, sigs...)
	}
	for _, r := range rrSets(req.Ns) {
		signer := zones.Matches(r[0].Header().Name)
		if signer == "" {
			continue
		}
		wc := wildcardFor(wildcard, r, state.QName())
		sigs, err := d.sign(r, signer, r[0].Header().Ttl, incep, expir, server, wc)
		if err != nil {
			return req, err
		}
		req.Ns = append(req.Ns, sigs...)
	}
	for _, r := range rrSets(req.Extra) {
		signer := zones.Matches(r[0].Header().Name)
		if signer == "" {
			continue
		}
		wc := wildcardFor(wildcard, r, state.QName())
		sigs, err := d.sign(r, signer, r[0].Header().Ttl, incep, expir, server, wc)
		if err != nil {
			return req, err
		}
		req.Extra = append(req.Extra, sigs...)
	}
	return req, nil
}

// sign signs the RRset rrs with all keys that apply to it. Signatures are cached by
// RRset content and are only reused for the same signer, wildcard owner (if any) and
// configured key tags, for at most ttl seconds. The wildcard argument is optional
// (at most one).
func (d Dnssec) sign(rrs []dns.RR, signerName string, ttl, incep, expir uint32, server string, wildcard ...string) ([]dns.RR, error) {
	if len(rrs) == 0 {
		return nil, nil
	}
	if len(d.keys) == 0 {
		// No key at all means we cannot sign. Serving an unsigned RRset would look
		// insecure to a validating client, so refuse instead.
		return nil, fmt.Errorf("no keys configured to sign %s %s", dns.TypeToString[rrs[0].Header().Rrtype], rrs[0].Header().Name)
	}
	wc := ""
	if len(wildcard) > 0 {
		wc = wildcard[0]
	}

	base := hash(rrs)
	k := d.cacheKey(base, wc)
	if sigs, ok := d.get(base, server, signerName, wc); ok {
		return sigs, nil
	}

	// The in-flight key includes the signing context, so concurrent requests for the
	// same RRset under different signers or wildcard owners do not share signatures.
	sigs, err := d.inflight.Do(k, func() (any, error) {
		var sigs []dns.RR
		for _, key := range d.keys {
			if d.splitkeys {
				if rrs[0].Header().Rrtype == dns.TypeDNSKEY {
					// We are signing a DNSKEY RRSet. With split keys, we need to use a KSK here.
					if !key.isKSK() {
						continue
					}
				} else {
					// For non-DNSKEY RRSets, we want to use a ZSK.
					if !key.isZSK() {
						continue
					}
				}
			}
			sig, e := key.signRRSet(rrs, signerName, ttl, incep, expir, wc)
			if e != nil {
				return nil, fmt.Errorf("key %d (algorithm %s) cannot sign %s %s: %w",
					key.tag, algorithm(key.K.Algorithm), dns.TypeToString[rrs[0].Header().Rrtype], rrs[0].Header().Name, e)
			}
			sigs = append(sigs, sig)
		}
		if len(sigs) == 0 {
			// Keys are configured but none of them may sign this RRset, e.g. split
			// keys with only a KSK. Do not fall through to an unsigned answer.
			return nil, fmt.Errorf("no key configured to sign %s %s", dns.TypeToString[rrs[0].Header().Rrtype], rrs[0].Header().Name)
		}
		// Publish the metadata before the signatures: a reader that finds the
		// signatures in the cache is then guaranteed to find the metadata too.
		d.setMeta(k, ttl, signerName)
		d.set(k, sigs)
		return sigs, nil
	})
	if err != nil {
		return nil, err
	}
	return sigs.([]dns.RR), nil
}

func (d Dnssec) set(key uint64, sigs []dns.RR) { d.cache.Add(key, sigs) }

// setMeta records the signing session the cached signatures belong to. The entry is
// valid for the TTL the RRset is served with, so cached signatures live as long as
// the data they sign. Very small TTLs are raised to minCacheTTL so a TTL of 0 does
// not force a re-sign per query: the cached signature is still served with the
// RRset's own TTL.
func (d Dnssec) setMeta(key uint64, ttl uint32, signer string) {
	if d.meta == nil {
		return
	}
	if ttl < minCacheTTL {
		ttl = minCacheTTL
	}
	d.meta.Add(key, cacheMeta{
		signer: signer,
		expire: time.Now().UTC().Add(time.Duration(ttl) * time.Second),
	})
}

// get returns the cached signatures for the RRset whose base hash is base. The
// key tags of the configured keys and the wildcard owner are folded into the cache
// key, so an entry is only found for the same key set and wildcard owner.
//
// Within a key set the signatures are selected by key tag: signatures of keys that
// are no longer configured are dropped, while signatures of keys that are still
// configured are kept. A rollover that has both the old and the new key configured
// therefore keeps serving the old signatures instead of rejecting them.
func (d Dnssec) get(base uint64, server string, signerWildcard ...string) ([]dns.RR, bool) {
	wc := ""
	var signer string
	if len(signerWildcard) > 0 {
		signer = signerWildcard[0]
	}
	if len(signerWildcard) > 1 {
		wc = signerWildcard[1]
	}
	key := d.cacheKey(base, wc)

	sigs, ok := d.cache.Get(key)
	if !ok {
		cacheMisses.WithLabelValues(server).Inc()
		return nil, false
	}

	now := time.Now().UTC()
	if d.meta != nil {
		m, ok := d.meta.Get(key)
		if !ok {
			// The metadata is published before the signatures, so this only happens
			// when the caches evicted the two parts at different times. Treat the
			// entry as a miss and leave it for the periodic cleaner.
			cacheMisses.WithLabelValues(server).Inc()
			return nil, false
		}
		if !m.expire.After(now) {
			d.cache.Remove(key)
			d.meta.Remove(key)
			cacheMisses.WithLabelValues(server).Inc()
			return nil, false
		}
		if len(signerWildcard) > 0 && m.signer != signer {
			cacheMisses.WithLabelValues(server).Inc()
			return nil, false
		}
	}

	// We sign for 8 days; once a signature has less than two days left the whole
	// RRset is signed again, so no configured key silently loses its signature.
	is75 := now.Add(twoDays)
	usable := make([]dns.RR, 0, len(sigs))
	for _, rr := range sigs {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		if !d.hasKeyTag(sig.KeyTag) {
			continue
		}
		if !sig.ValidityPeriod(is75) {
			cacheMisses.WithLabelValues(server).Inc()
			return nil, false
		}
		usable = append(usable, rr)
	}
	if len(usable) == 0 {
		cacheMisses.WithLabelValues(server).Inc()
		return nil, false
	}

	cacheHits.WithLabelValues(server).Inc()
	return usable, true
}

// hasKeyTag reports whether a key with the given tag is currently configured.
func (d Dnssec) hasKeyTag(tag uint16) bool {
	for _, k := range d.keys {
		if k.tag == tag {
			return true
		}
	}
	return false
}

// configuredTags returns the sorted key tags of the configured keys as a comma
// separated string. It identifies the key set a signature cache entry belongs to.
func (d Dnssec) configuredTags() string {
	if len(d.keys) == 0 {
		return ""
	}
	tags := make([]int, 0, len(d.keys))
	for _, k := range d.keys {
		tags = append(tags, int(k.tag))
	}
	slices.Sort(tags)
	var sb strings.Builder
	for i, t := range tags {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(strconv.Itoa(t))
	}
	return sb.String()
}

func incepExpir(now time.Time) (uint32, uint32) {
	incep := uint32(now.Add(-3 * time.Hour).Unix()) // #nosec G115 -- DNSSEC inception, Year 2106 problem accepted // -(2+1) hours, be sure to catch daylight saving time and such
	expir := uint32(now.Add(eightDays).Unix())      // #nosec G115 -- DNSSEC expiration, Year 2106 problem accepted      // sign for 8 days
	return incep, expir
}

// wildcardFor returns wildcard when rrs is the RRset that was synthesized from it
// for qname. Other RRSets in the same response (glue, CNAME targets) are not
// wildcard expansions and must be signed as-is.
func wildcardFor(wildcard string, rrs []dns.RR, qname string) string {
	if wildcard == "" || len(rrs) == 0 || !strings.HasPrefix(wildcard, "*.") {
		return ""
	}
	owner := rrs[0].Header().Name
	if !strings.EqualFold(owner, qname) || strings.HasPrefix(owner, "*.") {
		return ""
	}
	if !dns.IsSubDomain(dns.Fqdn(wildcard[2:]), owner) {
		return ""
	}
	return wildcard
}

func algorithm(a uint8) string {
	if s, ok := dns.AlgorithmToString[a]; ok {
		return s
	}
	return strconv.Itoa(int(a))
}

const (
	eightDays  = 8 * 24 * time.Hour
	twoDays    = 2 * 24 * time.Hour
	defaultCap = 10000 // default capacity of the cache.

	// minCacheTTL is the shortest time a signature is kept in the cache. It keeps
	// RRsets with a TTL of (close to) 0 from being signed again on every query;
	// the cached signature is still served with the RRset's own TTL.
	minCacheTTL = 5
)
