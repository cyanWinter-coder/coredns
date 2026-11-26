package dnssec

import (
	"context"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// ResponseWriter signs the response on the fly.
type ResponseWriter struct {
	dns.ResponseWriter
	d      Dnssec
	server string // server label for metrics.
	ctx    context.Context
}

// WriteMsg implements the dns.ResponseWriter interface.
func (d *ResponseWriter) WriteMsg(res *dns.Msg) error {
	// By definition we should sign anything that comes back, we should still figure out for
	// which zone it should be.
	state := request.Request{W: d.ResponseWriter, Req: res}

	zone := plugin.Zones(d.d.zones).Matches(state.Name())
	if zone == "" {
		return d.ResponseWriter.WriteMsg(res)
	}
	state.Zone = zone

	// The *file* plugin records the wildcard that synthesized this answer as
	// metadata. Pass it on so wildcard expansions get RRSIGs with the right
	// Labels field (RFC 4034 section 3.1.3).
	wildcard := wildcardFromContext(d.ctx)

	signed, err := d.d.signMessage(state, time.Now().UTC(), d.server, wildcard)
	if err != nil {
		writeServfail(d.ResponseWriter, res, zone, err)
		return nil
	}
	cacheSize.WithLabelValues(d.server, "signature").Set(float64(d.d.cache.Len()))
	// No need for EDNS0 trickery, as that is handled by the server.

	return d.ResponseWriter.WriteMsg(signed)
}

// Write implements the dns.ResponseWriter interface.
func (d *ResponseWriter) Write(buf []byte) (int, error) {
	log.Warning("Dnssec called with Write: not signing reply")
	n, err := d.ResponseWriter.Write(buf)
	return n, err
}
