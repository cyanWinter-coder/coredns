package metrics

import (
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnstest"

	"github.com/miekg/dns"
)

// Recorder is a dnstest.Recorder specific to the metrics plugin.
type Recorder struct {
	*dnstest.Recorder
	// Plugin holds the name of the plugin that wrote the response.
	// This is set automatically by the plugin chain via the PluginTracker interface.
	Plugin string
}

// NewRecorder makes and returns a new Recorder.
func NewRecorder(w dns.ResponseWriter) *Recorder { return &Recorder{Recorder: dnstest.NewRecorder(w)} }

// WriteMsg records the status code and calls the
// underlying ResponseWriter's WriteMsg method.
func (r *Recorder) WriteMsg(res *dns.Msg) error {
	return r.Recorder.WriteMsg(res)
}

// SetPlugin implements the plugin.PluginTracker interface. It also propagates
// the writing plugin to outer trackers such as health overload accounting.
func (r *Recorder) SetPlugin(name string) {
	r.Plugin = name
	if tracker, ok := r.ResponseWriter.(plugin.PluginTracker); ok {
		tracker.SetPlugin(name)
	}
}

// GetPlugin implements the plugin.PluginTracker interface.
func (r *Recorder) GetPlugin() string {
	return r.Plugin
}
