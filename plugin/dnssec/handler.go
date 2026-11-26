package dnssec

import (
	"context"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metadata"
	"github.com/coredns/coredns/plugin/metrics"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// ServeDNS implements the plugin.Handler interface.
func (d Dnssec) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	do := state.Do()
	qname := state.Name()
	qtype := state.QType()
	zone := plugin.Zones(d.zones).Matches(qname)
	if zone == "" {
		return plugin.NextOrFailure(d.Name(), d.Next, ctx, w, r)
	}

	state.Zone = zone
	server := metrics.WithServer(ctx)

	// Intercept queries for DNSKEY, but only if one of the zones matches the qname, otherwise we let
	// the query through.
	if qtype == dns.TypeDNSKEY {
		for _, z := range d.zones {
			if qname == z {
				resp := d.getDNSKEY(state, z, do, server)
				if resp.Rcode == dns.RcodeSuccess {
					resp.Authoritative = true
				}
				w.WriteMsg(resp)
				// The reply is written; report success so the server does not write
				// a second one, even when the SERVFAIL was already sent above.
				return dns.RcodeSuccess, nil
			}
		}
	}

	if do {
		drr := &ResponseWriter{ResponseWriter: w, d: d, server: server, ctx: ctx}
		return plugin.NextOrFailure(d.Name(), d.Next, ctx, drr, r)
	}

	return plugin.NextOrFailure(d.Name(), d.Next, ctx, w, r)
}

// Name implements the Handler interface.
func (d Dnssec) Name() string { return "dnssec" }

// writeServfail logs why a reply could not be signed and writes a SERVFAIL. Serving
// an unsigned reply would look insecure or bogus to a validating client, which is
// worse than failing the query.
//
// The response has been written by the time this returns, so callers must report a
// rcode that tells the server not to write again (plugin.ClientWrite semantics).
func writeServfail(w dns.ResponseWriter, req *dns.Msg, zone string, err error) (int, error) {
	log.Errorf("Failed to sign reply for %q in zone %q: %s", questionName(req), zone, err)
	m := servfailMsg(req)
	st := request.Request{W: w, Req: req}
	st.SizeAndDo(m)
	w.WriteMsg(m)
	return dns.RcodeSuccess, nil
}

// wildcardFromContext returns the wildcard owner that synthesized the answer for
// this request, if the serving plugin recorded it (see the *file* plugin). An empty
// string is returned when no metadata is available, which is the case when the
// metadata plugin is not enabled.
func wildcardFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	f := metadata.ValueFunc(ctx, "zone/wildcard")
	if f == nil {
		return ""
	}
	return f()
}
