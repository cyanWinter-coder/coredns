package health

import (
	"context"
	"time"

	"github.com/coredns/coredns/plugin"

	"github.com/miekg/dns"
)

// Name implements plugin.Handler.
func (h *health) Name() string { return "health" }

// ServeDNS tracks process-wide in-flight requests and records the responding
// plugin/rcode pair. Overload decisions themselves are made by OverloadMonitor
// and exposed on the health HTTP endpoint.
func (h *health) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	monitor := h.monitorOrDefault()
	monitor.IncInFlight()
	start := time.Now()
	defer func() {
		monitor.DecInFlight()
		monitor.RecordLatency(time.Since(start))
	}()

	recorder := NewTrackingWriter(w)
	status, err := plugin.NextOrFailure(h.Name(), h.Next, ctx, recorder, r)

	rc := recorder.Rcode
	if !plugin.ClientWrite(status) {
		// Match the prometheus plugin: when no response was written, the
		// returned status is the rcode the server will use.
		rc = status
	}
	pluginName := recorder.Plugin
	if pluginName == "" && h.Next != nil {
		pluginName = h.Next.Name()
	}
	RecordRequest(pluginName, rc)

	return status, err
}
