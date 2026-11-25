package health

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() { plugin.Register("health", setup) }

func setup(c *caddy.Controller) error {
	h, err := parseHealth(c)
	if err != nil {
		return plugin.Error("health", err)
	}
	// Health is process-wide: server blocks carrying the directive and all
	// health endpoints share one set of live signals, while retaining this
	// instance's parsed thresholds and hysteresis state.
	h.monitor = DefaultMonitor.withConfig(h.monitor.cfg)
	if strings.EqualFold(h.monitor.cfg.QueueSource, "runtime") {
		h.monitor.SetQueueDepthFunc(SchedulerQueueDepth)
	}

	c.OnStartup(h.OnStartup)
	c.OnRestart(h.OnReload)
	c.OnFinalShutdown(h.OnFinalShutdown)
	c.OnRestartFailed(h.OnStartup)

	// Test controllers and embedders that have not registered the DNS server
	// type may have a nil Caddy context; production setup always provides one.
	if c.Context() != nil {
		dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
			h.Next = next
			return h
		})
	}

	return nil
}

func parse(c *caddy.Controller) (string, time.Duration, error) {
	h, err := parseHealth(c)
	if err != nil {
		return "", 0, err
	}
	return h.Addr, h.lameduck, nil
}

func parseHealth(c *caddy.Controller) (*health, error) {
	addr := ""
	lame := time.Duration(0)
	cfg := OverloadConfig{RecoveryRatio: DefaultRecoveryRatio}

	for c.Next() {
		args := c.RemainingArgs()

		switch len(args) {
		case 0:
		case 1:
			addr = args[0]
			if _, _, e := net.SplitHostPort(addr); e != nil {
				return nil, e
			}
		default:
			return nil, c.ArgErr()
		}

		for c.NextBlock() {
			key := c.Val()
			args := c.RemainingArgs()

			switch key {
			case "lameduck":
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				l, err := time.ParseDuration(args[0])
				if err != nil {
					return nil, fmt.Errorf("unable to parse lameduck duration value: '%v' : %v", args[0], err)
				}
				lame = l

			case "overload":
				if len(args) > 0 {
					if err := parseOverloadPositional(c, args, &cfg); err != nil {
						return nil, err
					}
				}
				if err := parseOverloadBlock(c, &cfg); err != nil {
					return nil, err
				}

			default:
				if err := applyOverloadOption(c, key, args, &cfg); err != nil {
					if isUnknownOverloadOption(err) {
						return nil, c.Errf("unknown property '%s'", key)
					}
					return nil, err
				}
			}
		}
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &health{
		Addr:     addr,
		lameduck: lame,
		monitor:  NewOverloadMonitor(cfg),
	}, nil
}

func parseOverloadBlock(c *caddy.Controller, cfg *OverloadConfig) error {
	for c.NextBlock() {
		key := c.Val()
		args := c.RemainingArgs()
		if err := applyOverloadOption(c, key, args, cfg); err != nil {
			if isUnknownOverloadOption(err) {
				return c.Errf("unknown property '%s' in overload block", key)
			}
			return err
		}
	}
	return nil
}

type unknownOptionError struct{ key string }

func (e *unknownOptionError) Error() string { return "unknown overload option " + e.key }

func isUnknownOverloadOption(err error) bool {
	_, ok := err.(*unknownOptionError)
	return ok
}

func parseOverloadPositional(c *caddy.Controller, args []string, cfg *OverloadConfig) error {
	if len(args) > 3 {
		return c.ArgErr()
	}
	v, err := parseCountArg(args[0])
	if err != nil {
		return c.Errf("invalid inflight threshold %q: %v", args[0], err)
	}
	cfg.MaxInflight = v
	if len(args) >= 2 {
		v, err := parseCountArg(args[1])
		if err != nil {
			return c.Errf("invalid queue threshold %q: %v", args[1], err)
		}
		cfg.MaxQueueDepth = v
	}
	if len(args) == 3 {
		d, err := time.ParseDuration(args[2])
		if err != nil {
			return c.Errf("invalid latency threshold %q: %v", args[2], err)
		}
		cfg.MaxLatency = d
	}
	return nil
}

func applyOverloadOption(c *caddy.Controller, key string, args []string, cfg *OverloadConfig) error {
	requireOne := func() (string, error) {
		if len(args) != 1 {
			return "", c.ArgErr()
		}
		return args[0], nil
	}

	switch key {
	case "inflight_high", "inflight_high_watermark", "high_inflight",
		"high_inflight_threshold", "inflight", "inflight_threshold", "max_inflight", "max_in_flight",
		"max_inflight_requests", "max_in_flight_requests", "inflight_requests",
		"in_flight_threshold", "inflight_limit", "max_active_requests",
		"active_requests_threshold", "overload_threshold", "overload_inflight":
		v, err := requireOne()
		if err != nil {
			return err
		}
		n, err := parseCountArg(v)
		if err != nil {
			return c.Errf("invalid %s %q: %v", key, v, err)
		}
		cfg.MaxInflight = n

	case "inflight_low", "inflight_low_watermark", "low_inflight",
		"low_inflight_threshold", "inflight_recovery", "recovery_inflight",
		"inflight_recovery_threshold", "recovery_inflight_threshold":
		v, err := requireOne()
		if err != nil {
			return err
		}
		n, err := parseCountArg(v)
		if err != nil {
			return c.Errf("invalid %s %q: %v", key, v, err)
		}
		cfg.RecoveryInflight = n

	case "queue_high", "queue_high_watermark", "high_queue", "high_queue_threshold",
		"queue", "queue_threshold", "queue_backlog", "queue_backlog_threshold",
		"queue_size", "queue_length", "queue_limit", "max_queue", "max_queue_depth",
		"max_queue_size", "max_queue_length", "backlog", "backlog_threshold",
		"backlog_limit", "overload_queue":
		v, err := requireOne()
		if err != nil {
			return err
		}
		n, err := parseCountArg(v)
		if err != nil {
			return c.Errf("invalid %s %q: %v", key, v, err)
		}
		cfg.MaxQueueDepth = n

	case "queue_low", "queue_low_watermark", "low_queue", "low_queue_threshold",
		"queue_recovery", "recovery_queue", "recovery_queue_depth",
		"queue_recovery_threshold", "recovery_queue_threshold":
		v, err := requireOne()
		if err != nil {
			return err
		}
		n, err := parseCountArg(v)
		if err != nil {
			return c.Errf("invalid %s %q: %v", key, v, err)
		}
		cfg.RecoveryQueueDepth = n

	case "latency_high", "latency_high_watermark", "high_latency",
		"high_latency_threshold", "latency", "latency_threshold", "max_latency",
		"latency_limit", "overload_latency":
		v, err := requireOne()
		if err != nil {
			return err
		}
		d, err := time.ParseDuration(v)
		if err != nil {
			return c.Errf("invalid %s %q: %v", key, v, err)
		}
		cfg.MaxLatency = d

	case "latency_low", "latency_low_watermark", "low_latency",
		"low_latency_threshold", "latency_recovery", "recovery_latency",
		"latency_recovery_threshold", "recovery_latency_threshold":
		v, err := requireOne()
		if err != nil {
			return err
		}
		d, err := time.ParseDuration(v)
		if err != nil {
			return c.Errf("invalid %s %q: %v", key, v, err)
		}
		cfg.RecoveryLatency = d

	case "queue_source", "queue_backlog_source":
		v, err := requireOne()
		if err != nil {
			return err
		}
		cfg.QueueSource = v

	case "hysteresis", "hysteresis_ratio", "hysteresis_factor",
		"recovery_ratio", "recovery_threshold_ratio":
		v, err := requireOne()
		if err != nil {
			return err
		}
		r, err := parseRatio(v)
		if err != nil {
			return c.Errf("invalid %s %q: %v", key, v, err)
		}
		cfg.RecoveryRatio = r
		cfg.recoveryRatioSet = true

	default:
		return &unknownOptionError{key: key}
	}
	return nil
}

func parseCountArg(s string) (int64, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, fmt.Errorf("must be >= 0")
	}
	return n, nil
}

func parseRatio(s string) (float64, error) {
	percent := strings.HasSuffix(s, "%")
	if percent {
		s = strings.TrimSuffix(s, "%")
	}
	r, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, err
	}
	if percent {
		r /= 100
	} else if r > 1 && r <= 100 {
		// Accept the common percentage form without a trailing '%'.
		r /= 100
	}
	if r < 0 || r > 1 {
		return 0, fmt.Errorf("must be between 0 and 1 (or 0%% and 100%%)")
	}
	return r, nil
}
