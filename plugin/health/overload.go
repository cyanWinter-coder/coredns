package health

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	runtimemetrics "runtime/metrics"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/rcode"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Reason keywords exported in Snapshot.Reasons and the coredns_health_overloaded
// metric's reason label.
const (
	ReasonInflight = "inflight"
	ReasonQueue    = "queue_backlog"
	ReasonLatency  = "latency"
)

// DefaultRecoveryRatio is the low watermark used when an explicit recovery
// threshold is omitted: recover at or below 80% of the overload threshold.
const DefaultRecoveryRatio = 0.8

// defaultLatencyTTL expires an unused latency window so a burst cannot keep a
// drained node unhealthy forever.
const defaultLatencyTTL = 10 * time.Second

// OverloadConfig contains the high and low watermarks used by overload
// detection. A zero high watermark disables that signal.
type OverloadConfig struct {
	// MaxInflight is the high watermark for requests currently being served.
	MaxInflight int64 `json:"max_inflight,omitempty"`
	// MaxQueueDepth is the high watermark for queued work reported to the monitor.
	MaxQueueDepth int64 `json:"max_queue_depth,omitempty"`
	// MaxLatency is the high watermark for the averaged request latency.
	MaxLatency time.Duration `json:"max_latency_ns,omitempty"`

	// RecoveryInflight, RecoveryQueueDepth and RecoveryLatency are the low
	// watermarks. Zero values are derived from the corresponding Max value and
	// RecoveryRatio.
	RecoveryInflight   int64         `json:"recovery_inflight,omitempty"`
	RecoveryQueueDepth int64         `json:"recovery_queue_depth,omitempty"`
	RecoveryLatency    time.Duration `json:"recovery_latency_ns,omitempty"`

	// RecoveryRatio is the low/high watermark ratio used when a recovery
	// threshold is not set explicitly.
	RecoveryRatio float64 `json:"recovery_ratio,omitempty"`

	// LatencyTTL controls how long an observed latency average remains valid
	// without new samples. Zero uses defaultLatencyTTL.
	LatencyTTL time.Duration `json:"latency_ttl_ns,omitempty"`

	// QueueSource optionally selects a built-in backlog source. "runtime"
	// samples runnable Go goroutines, which are waiting for CPU/service.
	// Empty/"reported" uses SetQueueDepth/Enqueue/Dequeue values.
	QueueSource string `json:"queue_source,omitempty"`

	// recoveryRatioSet distinguishes an explicit zero ratio from an unset one.
	recoveryRatioSet bool
}

// Config is an alias kept for callers that prefer the shorter name.
type Config = OverloadConfig

// Thresholds is an alias describing the configuration's role.
type Thresholds = OverloadConfig

// Snapshot is a point-in-time, race-free view of overload state.
type Snapshot struct {
	Overloaded  bool           `json:"overloaded"`
	Reason      string         `json:"reason"`
	Reasons     []string       `json:"reasons"`
	Message     string         `json:"message,omitempty"`
	Inflight    int64          `json:"inflight"`
	QueueDepth  int64          `json:"queue_depth"`
	Latency     time.Duration  `json:"latency_ns"`
	LatencyText string         `json:"latency,omitempty"`
	Since       time.Time      `json:"since,omitempty"`
	Thresholds  OverloadConfig `json:"thresholds"`
}

// overloadSignals holds the hot-path counters. A process-wide signal set can
// be shared by monitors with different thresholds while keeping unit-test
// monitors isolated.
type overloadSignals struct {
	inflight       atomic.Int64
	queue          atomic.Int64
	latencySum     atomic.Int64
	latencyCount   atomic.Int64
	latencyLast    atomic.Int64 // time.Duration in nanoseconds
	latencyUpdated atomic.Int64 // unix nanoseconds

	queueFnMu sync.RWMutex
	queueFn   func() int64
}

// OverloadMonitor evaluates inflight, queue and latency signals with high/low
// watermarks. The hot request path uses atomics; Evaluate takes a state mutex
// at probe/metrics scrape frequency rather than once per DNS request.
type OverloadMonitor struct {
	cfg OverloadConfig
	sig *overloadSignals

	stateMu sync.RWMutex
	state   Snapshot
}

// Monitor is a short alias for OverloadMonitor.
type Monitor = OverloadMonitor

// DefaultMonitor is the process-wide monitor used when a health handler is
// created without an explicit one.
var DefaultMonitor = NewOverloadMonitor(OverloadConfig{})

// NewOverloadMonitor creates an overload monitor from cfg and normalizes the
// hysteresis watermarks.
func NewOverloadMonitor(cfg OverloadConfig) *OverloadMonitor {
	cfg = normalizeConfig(cfg)
	sig := &overloadSignals{}
	if strings.EqualFold(cfg.QueueSource, "runtime") {
		sig.queueFn = SchedulerQueueDepth
	}
	m := &OverloadMonitor{cfg: cfg, sig: sig}
	m.state = Snapshot{
		Reason:     "ok",
		Reasons:    []string{},
		Thresholds: cfg,
	}
	return m
}

// withConfig returns a monitor that shares m's hot-path signals but uses cfg
// and its own hysteresis state. Setup uses it to make all health endpoints in
// one process observe the same inflight/queue/latency values.
func (m *OverloadMonitor) withConfig(cfg OverloadConfig) *OverloadMonitor {
	cfg = normalizeConfig(cfg)
	next := &OverloadMonitor{cfg: cfg, sig: m.sig}
	next.state = Snapshot{Reason: "ok", Reasons: []string{}, Thresholds: cfg}
	return next
}

// NewMonitor is an alias for NewOverloadMonitor.
func NewMonitor(cfg OverloadConfig) *OverloadMonitor { return NewOverloadMonitor(cfg) }

// Config returns a copy of the normalized thresholds.
func (m *OverloadMonitor) Config() OverloadConfig {
	if m == nil {
		return OverloadConfig{}
	}
	return m.cfg
}

func normalizeConfig(cfg OverloadConfig) OverloadConfig {
	if cfg.RecoveryRatio == 0 && !cfg.recoveryRatioSet {
		cfg.RecoveryRatio = DefaultRecoveryRatio
	}
	if cfg.LatencyTTL == 0 {
		cfg.LatencyTTL = defaultLatencyTTL
	}
	if cfg.MaxInflight > 0 && cfg.RecoveryInflight == 0 {
		cfg.RecoveryInflight = int64(math.Floor(float64(cfg.MaxInflight) * cfg.RecoveryRatio))
	}
	if cfg.MaxQueueDepth > 0 && cfg.RecoveryQueueDepth == 0 {
		cfg.RecoveryQueueDepth = int64(math.Floor(float64(cfg.MaxQueueDepth) * cfg.RecoveryRatio))
	}
	if cfg.MaxLatency > 0 && cfg.RecoveryLatency == 0 {
		cfg.RecoveryLatency = time.Duration(float64(cfg.MaxLatency) * cfg.RecoveryRatio)
	}
	return cfg
}

// Validate checks threshold ordering and ranges.
func (cfg OverloadConfig) Validate() error {
	if cfg.MaxInflight < 0 || cfg.MaxQueueDepth < 0 {
		return fmt.Errorf("overload counts must not be negative")
	}
	if cfg.MaxLatency < 0 {
		return fmt.Errorf("overload latency must not be negative")
	}
	if cfg.RecoveryInflight < 0 || cfg.RecoveryQueueDepth < 0 || cfg.RecoveryLatency < 0 {
		return fmt.Errorf("recovery thresholds must not be negative")
	}
	if cfg.RecoveryRatio < 0 || cfg.RecoveryRatio > 1 {
		return fmt.Errorf("recovery ratio must be between 0 and 1")
	}
	if cfg.MaxInflight > 0 && cfg.RecoveryInflight > cfg.MaxInflight {
		return fmt.Errorf("inflight recovery threshold %d exceeds overload threshold %d", cfg.RecoveryInflight, cfg.MaxInflight)
	}
	if cfg.MaxQueueDepth > 0 && cfg.RecoveryQueueDepth > cfg.MaxQueueDepth {
		return fmt.Errorf("queue recovery threshold %d exceeds overload threshold %d", cfg.RecoveryQueueDepth, cfg.MaxQueueDepth)
	}
	if cfg.MaxLatency > 0 && cfg.RecoveryLatency > cfg.MaxLatency {
		return fmt.Errorf("latency recovery threshold %s exceeds overload threshold %s", cfg.RecoveryLatency, cfg.MaxLatency)
	}
	if cfg.RecoveryInflight > 0 && cfg.MaxInflight == 0 {
		return fmt.Errorf("inflight recovery threshold requires an inflight threshold")
	}
	if cfg.RecoveryQueueDepth > 0 && cfg.MaxQueueDepth == 0 {
		return fmt.Errorf("queue recovery threshold requires a queue threshold")
	}
	if cfg.RecoveryLatency > 0 && cfg.MaxLatency == 0 {
		return fmt.Errorf("latency recovery threshold requires a latency threshold")
	}
	switch strings.ToLower(cfg.QueueSource) {
	case "", "reported", "manual", "runtime":
	default:
		return fmt.Errorf("unsupported queue_source %q", cfg.QueueSource)
	}
	return nil
}

// IncInFlight adds one in-flight request and returns the new count.
func (m *OverloadMonitor) IncInFlight() int64 { return m.sig.inflight.Add(1) }

// DecInFlight removes one in-flight request and returns the new count.
func (m *OverloadMonitor) DecInFlight() int64 { return m.sig.inflight.Add(-1) }

// AddInFlight adds delta to the in-flight count.
func (m *OverloadMonitor) AddInFlight(delta int64) int64 { return m.sig.inflight.Add(delta) }

// SetInFlight replaces the in-flight count. It is primarily useful in tests
// and adapters that source the value externally.
func (m *OverloadMonitor) SetInFlight(v int64) { m.sig.inflight.Store(v) }

// InFlight returns the current in-flight count.
func (m *OverloadMonitor) InFlight() int64 { return m.sig.inflight.Load() }

// Enqueue increments the reported queue backlog.
func (m *OverloadMonitor) Enqueue() int64 { return m.sig.queue.Add(1) }

// Dequeue decrements the reported queue backlog.
func (m *OverloadMonitor) Dequeue() int64 { return m.sig.queue.Add(-1) }

// IncQueueDepth increments the reported queue backlog.
func (m *OverloadMonitor) IncQueueDepth() int64 { return m.Enqueue() }

// DecQueueDepth decrements the reported queue backlog.
func (m *OverloadMonitor) DecQueueDepth() int64 { return m.Dequeue() }

// AddQueueDepth adds delta to the reported queue backlog.
func (m *OverloadMonitor) AddQueueDepth(delta int64) int64 { return m.sig.queue.Add(delta) }

// SetQueueDepth replaces the queue backlog.
func (m *OverloadMonitor) SetQueueDepth(v int64) { m.sig.queue.Store(v) }

// QueueDepth returns the reported queue backlog.
func (m *OverloadMonitor) QueueDepth() int64 { return m.sig.queue.Load() }

// SetQueueDepthFunc installs an external backlog source, sampled once per
// Evaluate call. It is intended for a real request/upstream queue adapter.
func (m *OverloadMonitor) SetQueueDepthFunc(fn func() int64) {
	m.sig.queueFnMu.Lock()
	m.sig.queueFn = fn
	m.sig.queueFnMu.Unlock()
}

// SchedulerQueueDepth returns the number of goroutines currently runnable but
// waiting to be scheduled. In CoreDNS's goroutine-per-query model this is a
// useful built-in proxy for CPU/processing queue backlog.
func SchedulerQueueDepth() int64 {
	sample := []runtimemetrics.Sample{{Name: "/sched/goroutines:runnable"}}
	runtimemetrics.Read(sample)
	if sample[0].Value.Kind() == runtimemetrics.KindUint64 {
		return int64(sample[0].Value.Uint64())
	}
	return 0
}

// RecordLatency adds a request latency sample. Samples are averaged between
// Evaluate calls, keeping the hot path to two atomic additions.
func (m *OverloadMonitor) RecordLatency(d time.Duration) {
	if m == nil || d < 0 {
		return
	}
	m.sig.latencySum.Add(int64(d))
	m.sig.latencyCount.Add(1)
	m.sig.latencyUpdated.Store(time.Now().UnixNano())
}

// ObserveLatency is the Prometheus-style alias for RecordLatency.
func (m *OverloadMonitor) ObserveLatency(d time.Duration) { m.RecordLatency(d) }

// Latency returns the most recently evaluated average latency.
func (m *OverloadMonitor) Latency() time.Duration {
	return time.Duration(m.sig.latencyLast.Load())
}

// flushLatency converts accumulated samples into the interval average. It
// retains the previous average while no samples arrive until LatencyTTL.
func (m *OverloadMonitor) flushLatency(now time.Time) time.Duration {
	sum := m.sig.latencySum.Swap(0)
	n := m.sig.latencyCount.Swap(0)
	if n > 0 {
		avg := time.Duration(sum / n)
		m.sig.latencyLast.Store(int64(avg))
		return avg
	}

	last := time.Duration(m.sig.latencyLast.Load())
	if last > 0 {
		updated := time.Unix(0, m.sig.latencyUpdated.Load())
		if !updated.IsZero() && now.Sub(updated) > m.cfg.LatencyTTL {
			m.sig.latencyLast.Store(0)
			return 0
		}
	}
	return last
}

type signalStatus struct {
	kind      string
	value     string
	high      string
	low       string
	aboveHigh bool
	aboveLow  bool
}

// Evaluate recomputes overload state using the hysteresis watermarks and
// updates the process metrics.
func (m *OverloadMonitor) Evaluate() Snapshot {
	if m == nil {
		return Snapshot{Overloaded: false, Reason: "ok", Reasons: []string{}}
	}

	now := time.Now()
	m.sig.queueFnMu.RLock()
	queueFn := m.sig.queueFn
	m.sig.queueFnMu.RUnlock()
	if queueFn != nil {
		m.sig.queue.Store(queueFn())
	}

	inflight := m.sig.inflight.Load()
	queue := m.sig.queue.Load()
	latency := m.flushLatency(now)

	signals := []signalStatus{}
	if m.cfg.MaxInflight > 0 {
		signals = append(signals, signalStatus{
			kind: ReasonInflight, value: fmt.Sprint(inflight),
			high: fmt.Sprint(m.cfg.MaxInflight), low: fmt.Sprint(m.cfg.RecoveryInflight),
			aboveHigh: inflight > m.cfg.MaxInflight, aboveLow: inflight > m.cfg.RecoveryInflight,
		})
	}
	if m.cfg.MaxQueueDepth > 0 {
		signals = append(signals, signalStatus{
			kind: ReasonQueue, value: fmt.Sprint(queue),
			high: fmt.Sprint(m.cfg.MaxQueueDepth), low: fmt.Sprint(m.cfg.RecoveryQueueDepth),
			aboveHigh: queue > m.cfg.MaxQueueDepth, aboveLow: queue > m.cfg.RecoveryQueueDepth,
		})
	}
	if m.cfg.MaxLatency > 0 {
		signals = append(signals, signalStatus{
			kind: ReasonLatency, value: latency.String(),
			high: m.cfg.MaxLatency.String(), low: m.cfg.RecoveryLatency.String(),
			aboveHigh: latency > m.cfg.MaxLatency, aboveLow: latency > m.cfg.RecoveryLatency,
		})
	}

	highKinds := map[string]bool{}
	recoveryKinds := map[string]bool{}
	for _, s := range signals {
		if s.aboveHigh {
			highKinds[s.kind] = true
		}
		if s.aboveLow {
			recoveryKinds[s.kind] = true
		}
	}

	m.stateMu.Lock()
	wasOverloaded := m.state.Overloaded
	overloaded := len(highKinds) > 0 || (wasOverloaded && len(recoveryKinds) > 0)

	reasons := make([]string, 0, len(signals))
	messages := make([]string, 0, len(signals))
	for _, s := range signals {
		switch {
		case highKinds[s.kind]:
			reasons = append(reasons, s.kind)
			messages = append(messages, fmt.Sprintf("%s=%s exceeds overload threshold %s; recover at <=%s", s.kind, s.value, s.high, s.low))
		case overloaded && recoveryKinds[s.kind]:
			reasons = append(reasons, s.kind)
			messages = append(messages, fmt.Sprintf("%s=%s is in hysteresis band; recover at <=%s", s.kind, s.value, s.low))
		}
	}
	if len(reasons) == 0 {
		reasons = []string{}
	}

	var since time.Time
	switch {
	case overloaded && !wasOverloaded:
		since = now
	case overloaded:
		since = m.state.Since
	default:
		since = time.Time{}
	}

	reason := "ok"
	message := ""
	if overloaded {
		reason = strings.Join(reasons, ",")
		message = strings.Join(messages, "; ")
	}

	snapshot := Snapshot{
		Overloaded:  overloaded,
		Reason:      reason,
		Reasons:     append([]string{}, reasons...),
		Message:     message,
		Inflight:    inflight,
		QueueDepth:  queue,
		Latency:     latency,
		LatencyText: latency.String(),
		Since:       since,
		Thresholds:  m.cfg,
	}
	m.state = snapshot
	m.stateMu.Unlock()

	m.updateMetrics(snapshot)
	return snapshot
}

// State returns the current evaluated snapshot.
func (m *OverloadMonitor) State() Snapshot { return m.Evaluate() }

// SnapshotState is an alias for State that avoids confusion with the Snapshot type.
func (m *OverloadMonitor) SnapshotState() Snapshot { return m.Evaluate() }

// IsOverloaded reports whether the node is currently unhealthy due to overload.
func (m *OverloadMonitor) IsOverloaded() bool { return m.Evaluate().Overloaded }

// Overloaded is an alias for IsOverloaded.
func (m *OverloadMonitor) Overloaded() bool { return m.IsOverloaded() }

// OverloadedState is an alias for IsOverloaded.
func (m *OverloadMonitor) OverloadedState() bool { return m.IsOverloaded() }

// Check returns the overload decision and machine-readable reason.
func (m *OverloadMonitor) Check() (bool, string) {
	s := m.Evaluate()
	return s.Overloaded, s.Reason
}

// Reason evaluates and returns the current reason ("ok" when healthy).
func (m *OverloadMonitor) Reason() string { return m.Evaluate().Reason }

// CurrentReason returns the last evaluated reason without recomputing state.
func (m *OverloadMonitor) CurrentReason() string {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	return m.state.Reason
}

func (m *OverloadMonitor) updateMetrics(s Snapshot) {
	InFlightMetric.Set(float64(s.Inflight))
	QueueDepthMetric.Set(float64(s.QueueDepth))
	LatencyMetric.Set(s.Latency.Seconds())
	for _, reason := range overloadReasonLabels {
		value := 0.0
		for _, active := range s.Reasons {
			if active == reason {
				value = 1
				break
			}
		}
		OverloadedMetric.WithLabelValues(reason).Set(value)
	}
}

var overloadReasonLabels = []string{ReasonInflight, ReasonQueue, ReasonLatency}

// RecordRequest counts a completed DNS request by responding plugin and rcode.
// Label cardinality is bounded by the compiled-in plugin names and DNS rcodes.
func RecordRequest(pluginName string, rcodeValue int) {
	if pluginName == "" {
		pluginName = "unknown"
	}
	RequestTotal.WithLabelValues(pluginName, rcode.ToString(rcodeValue)).Inc()
}

// TrackingWriter records the final DNS rcode and responding plugin.
type TrackingWriter struct {
	dns.ResponseWriter
	Rcode  int
	Plugin string
}

// NewTrackingWriter wraps w.
func NewTrackingWriter(w dns.ResponseWriter) *TrackingWriter {
	return &TrackingWriter{ResponseWriter: w, Rcode: dns.RcodeSuccess}
}

// WriteMsg records the rcode before forwarding the response.
func (w *TrackingWriter) WriteMsg(m *dns.Msg) error {
	w.Rcode = m.Rcode
	return w.ResponseWriter.WriteMsg(m)
}

// SetPlugin implements plugin.PluginTracker.
func (w *TrackingWriter) SetPlugin(name string) { w.Plugin = name }

// GetPlugin implements plugin.PluginTracker.
func (w *TrackingWriter) GetPlugin() string { return w.Plugin }

var (
	// RequestTotal counts DNS requests observed by overload detection by plugin and rcode.
	RequestTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "health",
		Name:      "overload_requests_total",
		Help:      "Total DNS requests observed by health overload detection, by plugin and response code.",
	}, []string{"plugin", "rcode"})

	// OverloadedMetric reports whether a node is currently overloaded for a reason.
	OverloadedMetric = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "health",
		Name:      "overloaded",
		Help:      "Whether health overload detection currently considers this instance overloaded, by reason.",
	}, []string{"reason"})

	// InFlightMetric exports the current in-flight DNS request count.
	InFlightMetric = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "health",
		Name:      "inflight_requests",
		Help:      "Current number of in-flight DNS requests observed by the health plugin.",
	})

	// QueueDepthMetric exports the reported queue backlog.
	QueueDepthMetric = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "health",
		Name:      "queue_depth",
		Help:      "Current queue backlog reported to health overload detection.",
	})

	// LatencyMetric exports the current averaged request latency.
	LatencyMetric = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "health",
		Name:      "request_latency_seconds_current",
		Help:      "Current averaged DNS request latency used by health overload detection.",
	})
)
