package dnssec

import (
	"encoding/binary"
	"hash/fnv"
	"io"
	"time"

	"github.com/coredns/coredns/plugin/pkg/cache"

	"github.com/miekg/dns"
)

// hash serializes the RRset and returns the base signature cache key. Use
// Dnssec.cacheKey on top of it: that folds in the properties that make otherwise
// identical RRSets produce different signatures.
func hash(rrs []dns.RR) uint64 {
	h := fnv.New64()
	// we need to hash the entire RRset to pick the correct sig, if the rrset
	// changes for whatever reason we should resign.
	// We could use wirefmt, or the string format, both create garbage when creating
	// the hash key. And of course is a uint64 big enough?
	for _, rr := range rrs {
		io.WriteString(h, rr.String())
	}
	return h.Sum64()
}

// cacheKey derives the real cache key from the RRset base hash. It folds in the
// wildcard owner the RRset was synthesized from and the tags of the configured keys.
//
// The key tags make signatures cached for one key set invisible to another one, so
// a rollover that changes the key set never returns stale signatures; if the old and
// the new key are configured together, the key set is unchanged and the signatures
// of both keys keep being served. The wildcard owner is needed because a wildcard
// expansion is signed over the wildcard name, which is not visible in the RRset.
//
// The signer name is not part of the key: it follows from the RRset owner (it is the
// configured zone that contains the name), so for one Dnssec instance the same RRset
// always has the same signer. It is verified against the cache metadata instead.
func (d Dnssec) cacheKey(base uint64, wildcard string) uint64 {
	h := fnv.New64()
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], base)
	h.Write(b[:])
	if wildcard != "" {
		io.WriteString(h, "\x00"+wildcard)
	}
	io.WriteString(h, "\x00"+d.configuredTags())
	return h.Sum64()
}

// periodicClean cleans the signature cache. The optional metadata cache holds the TTL
// and signer of each signature cache entry and is cleaned alongside it.
func periodicClean(c *cache.Cache[[]dns.RR], stop <-chan struct{}, metaCache ...*cache.Cache[cacheMeta]) {
	var meta *cache.Cache[cacheMeta]
	if len(metaCache) > 0 {
		meta = metaCache[0]
	}
	tick := time.NewTicker(8 * time.Hour)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			// we sign for 8 days, check if a signature in the cache reached 75% of that (i.e. 6), if found delete
			// the signature
			is75 := time.Now().UTC().Add(twoDays)
			c.Walk(func(items map[uint64][]dns.RR, key uint64) bool {
				for _, rr := range items[key] {
					sig, ok := rr.(*dns.RRSIG)
					if !ok || !sig.ValidityPeriod(is75) {
						delete(items, key)
						if meta != nil {
							meta.Remove(key)
						}
						break
					}
				}
				return true
			})
			if meta != nil {
				now := time.Now().UTC()
				meta.Walk(func(items map[uint64]cacheMeta, key uint64) bool {
					if m, ok := items[key]; ok && !m.expire.After(now) {
						delete(items, key)
					}
					return true
				})
			}

		case <-stop:
			return
		}
	}
}
