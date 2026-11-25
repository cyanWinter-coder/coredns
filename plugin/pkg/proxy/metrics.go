package proxy

import (
	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Variables declared for monitoring.
var (
	requestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace:                   plugin.Namespace,
		Subsystem:                   "proxy",
		Name:                        "request_duration_seconds",
		Buckets:                     plugin.TimeBuckets,
		NativeHistogramBucketFactor: plugin.NativeHistogramBucketFactor,
		Help:                        "Histogram of the time each request took.",
	}, []string{"proxy_name", "to", "rcode"})

	healthcheckFailureCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "proxy",
		Name:      "healthcheck_failures_total",
		Help:      "Counter of the number of failed healthchecks.",
	}, []string{"proxy_name", "to"})

	connCacheHitsCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "proxy",
		Name:      "conn_cache_hits_total",
		Help:      "Counter of connection cache hits per upstream and protocol.",
	}, []string{"proxy_name", "to", "proto"})

	connCacheMissesCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "proxy",
		Name:      "conn_cache_misses_total",
		Help:      "Counter of connection cache misses per upstream and protocol.",
	}, []string{"proxy_name", "to", "proto"})

	requestTotalCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "proxy",
		Name:      "requests_total",
		Help:      "Counter of requests sent to each upstream, including failed ones.",
	}, []string{"proxy_name", "to"})

	requestFailureCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "proxy",
		Name:      "request_failures_total",
		Help:      "Counter of requests to each upstream that failed with a network or timeout error.",
	}, []string{"proxy_name", "to"})

	upstreamStatus = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "proxy",
		Name:      "upstream_status",
		Help:      "Circuit-breaker state of each upstream (1 = closed/healthy, 0.5 = half-open/recovering, 0 = open/removed).",
	}, []string{"proxy_name", "to", "state"})
)

// publishStatus keeps the upstream_status gauge consistent with breaker transitions:
// the current state label carries 1, every other state 0.
func publishStatus(proxyName, addr string, state State) {
	for _, s := range []State{StateClosed, StateHalfOpen, StateOpen} {
		v := 0.0
		if s == state {
			v = 1
		}
		upstreamStatus.WithLabelValues(proxyName, addr, s.String()).Set(v)
	}
}
