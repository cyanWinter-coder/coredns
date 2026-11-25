package file

import (
	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	zoneTransfers = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "file",
		Name:      "zone_transfers_total",
		Help:      "Total zone transfer attempts by zone, protocol and result.",
	}, []string{"zone", "protocol", "result"})

	zoneTransferDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: plugin.Namespace,
		Subsystem: "file",
		Name:      "zone_transfer_duration_seconds",
		Help:      "Zone transfer duration in seconds.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"zone", "protocol", "result"})

	zoneNotifies = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "file",
		Name:      "zone_notifications_total",
		Help:      "Total inbound and outbound zone notification events by direction and result.",
	}, []string{"zone", "direction", "result"})
)

func recordTransfer(zone, protocol, result string) {
	zoneTransfers.WithLabelValues(zone, protocol, result).Inc()
}

func recordNotify(zone, direction, result string) {
	zoneNotifies.WithLabelValues(zone, direction, result).Inc()
}
