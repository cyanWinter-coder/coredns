// Package health implements an HTTP handler that responds to health checks.
package health

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/reuseport"
)

var log = clog.NewWithPlugin("health")

// Health implements healthchecks by exporting a HTTP endpoint.
type health struct {
	Addr      string
	lameduck  time.Duration
	healthURI *url.URL

	monitor     *OverloadMonitor
	lameducking atomic.Bool

	ln      net.Listener
	srv     *http.Server
	nlSetup bool
	mux     *http.ServeMux

	Next plugin.Handler
	stop context.CancelFunc
}

const shutdownTimeout = 5 * time.Second

func (h *health) OnStartup() error {
	if h.Addr == "" {
		h.Addr = ":8080"
	}
	if h.monitor == nil {
		h.monitor = DefaultMonitor
	}

	var err error
	h.healthURI, err = url.Parse("http://" + h.Addr)
	if err != nil {
		return err
	}

	h.healthURI.Path = "/health"
	if h.healthURI.Host == "" {
		// while we can listen on multiple network interfaces, we need to pick one to poll
		h.healthURI.Host = "localhost"
	}

	ln, err := reuseport.Listen("tcp", h.Addr)
	if err != nil {
		return err
	}

	h.ln = ln
	h.mux = http.NewServeMux()
	h.nlSetup = true

	h.mux.HandleFunc(h.healthURI.Path, h.serveHealth)
	h.mux.HandleFunc("/health/state", h.serveState)

	ctx := context.Background()
	ctx, h.stop = context.WithCancel(ctx)

	h.srv = &http.Server{
		Handler:      h.mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  5 * time.Second,
	}

	go func() { h.srv.Serve(h.ln) }()
	go func() { h.overloaded(ctx) }()

	return nil
}

func (h *health) monitorOrDefault() *OverloadMonitor {
	if h.monitor != nil {
		return h.monitor
	}
	return DefaultMonitor
}

// Overloaded reports the current overload decision for this health instance.
func (h *health) Overloaded() bool { return h.monitorOrDefault().IsOverloaded() }

// Reason evaluates and returns the current overload reason.
func (h *health) Reason() string { return h.monitorOrDefault().Reason() }

// serveHealth keeps the original /health contract: HTTP 200 and body "OK"
// when healthy. When overload thresholds are tripped it returns 503 and a
// plain-text reason without changing the probe path.
func (h *health) serveHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead+", "+http.MethodOptions)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if h.lameducking.Load() {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, http.StatusText(http.StatusOK))
		return
	}

	status := h.monitorOrDefault().Evaluate()
	w.Header().Set("X-CoreDNS-Health-Reason", status.Reason)
	if !status.Overloaded {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, http.StatusText(http.StatusOK))
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	io.WriteString(w, "overloaded: ")
	io.WriteString(w, status.Message)
	io.WriteString(w, "\n")
}

// serveState exposes the full machine-readable overload state and reasons.
func (h *health) serveState(w http.ResponseWriter, _r *http.Request) {
	status := h.monitorOrDefault().Evaluate()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-CoreDNS-Health-Reason", status.Reason)
	if status.Overloaded {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_ = json.NewEncoder(w).Encode(status)
}

func (h *health) OnFinalShutdown() error {
	if !h.nlSetup {
		return nil
	}

	if h.lameduck > 0 {
		log.Infof("Going into lameduck mode for %s", h.lameduck)
		// The documented health behavior during lameduck is to keep answering
		// OK; the ready plugin is responsible for removing traffic.
		h.lameducking.Store(true)
		time.Sleep(h.lameduck)
	}

	h.stop()

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := h.srv.Shutdown(ctx); err != nil {
		log.Infof("Failed to stop health http server: %s", err)
	}
	h.nlSetup = false
	return nil
}

func (h *health) OnReload() error {
	if !h.nlSetup {
		return nil
	}

	h.stop()

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := h.srv.Shutdown(ctx); err != nil {
		log.Infof("Failed to stop health http server: %s", err)
	}
	h.nlSetup = false
	return nil
}
