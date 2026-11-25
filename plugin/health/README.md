# health

## Name

*health* - enables a health check endpoint.

## Description

Enabled process wide health endpoint. When CoreDNS is up and running this returns a 200 OK HTTP
status code. The health is exported, by default, on port 8080/health.

## Syntax

~~~
health [ADDRESS]
~~~

Optionally takes an address; the default is `:8080`. The health path is fixed to `/health`. The
health endpoint returns a 200 response code and the word "OK" when this server is healthy.

An extra option can be set with this extended syntax:

~~~
health [ADDRESS] {
    lameduck DURATION
    inflight_threshold COUNT
    queue_threshold COUNT
    latency_threshold DURATION
    recovery_ratio RATIO
    inflight_recovery COUNT
    queue_recovery COUNT
    latency_recovery DURATION
}
~~~

* `lameduck` will delay shutdown for **DURATION**. /health will still answer 200 OK.
  Note: The *ready* plugin will not answer OK while CoreDNS is in lame duck mode prior to shutdown.
* `inflight_threshold` fails `/health` when the number of requests currently inside the
  health plugin is greater than **COUNT**. Zero disables this signal.
* `queue_threshold` fails `/health` when the reported queue backlog is greater than **COUNT**.
  Queue producers can feed the same monitor with `SetQueueDepth`, `Enqueue`, and `Dequeue`.
  Set `queue_source runtime` to use runnable Go goroutines as a built-in scheduling-backlog proxy.
* `latency_threshold` fails `/health` when the interval-average DNS request latency is greater
  than **DURATION**.
* `recovery_ratio` sets the low watermark as a fraction of each high threshold. The default is
  `0.8`; recovery happens at or below 80% of the overload threshold. Percent values such as
  `80%` are also accepted.
* `inflight_recovery`, `queue_recovery`, and `latency_recovery` set explicit low watermarks and
  override `recovery_ratio` for that signal.

The same options may be grouped in an `overload` block:

~~~ corefile
health :8080 {
    overload {
        inflight 20000
        queue 4000
        latency 50ms
        hysteresis 0.75
    }
}
~~~

The high and low watermarks form a hysteresis band. For example, with
`inflight_threshold 10000` and the default recovery ratio, the instance is removed after more
than 10000 requests are in flight, but it does not become healthy again until in-flight drops to
8000 or below. This prevents readiness probes from flapping at the threshold.

When overloaded, `GET /health` returns `503 Service Unavailable` and a plain-text explanation.
The original healthy response remains exactly `200 OK` with body `OK`. `GET /health/state`
returns the same state as JSON, including all current signal values, active reasons, and
thresholds. The active reason is also returned in the `X-CoreDNS-Health-Reason` header.

If you have multiple Server Blocks, *health* can only be enabled in one of them (as it is process
wide). If you really need multiple endpoints, you must run health endpoints on different ports:

~~~ corefile
com {
    whoami
    health :8080
}

net {
    erratic
    health :8081
}
~~~

Doing this is supported but both endpoints ":8080" and ":8081" will export the exact same health.

## Metrics

If monitoring is enabled (via the *prometheus* plugin) then the following metrics are exported:

 * `coredns_health_request_duration_seconds{}` - The *health* plugin performs a self health check
    once per second on the `/health` endpoint. This metric is the duration to process that request.
    As this is a local operation it should be fast. A (large) increase in this
    duration indicates the CoreDNS process is having trouble keeping up with its query load.
 * `coredns_health_request_failures_total{}` - The number of times the self health check failed.
 * `coredns_health_probe_responses_total{status}` - Local self-probe responses by HTTP status.
 * `coredns_health_overload_requests_total{plugin, rcode}` - DNS requests observed by overload
    detection, bounded by the responding plugin and DNS response code.
 * `coredns_health_overloaded{reason}` - `1` while this instance is overloaded for `reason`
    (`inflight`, `queue_backlog`, or `latency`), otherwise `0`.
 * `coredns_health_inflight_requests{}` - Current in-flight DNS requests.
 * `coredns_health_queue_depth{}` - Current reported queue backlog.
 * `coredns_health_request_latency_seconds_current{}` - Current averaged request latency.

Prometheus adds the scrape `instance` label, so
`max by (instance) (coredns_health_overloaded == 1)` identifies the overloaded nodes without
adding high-cardinality node, query-name, or zone labels to the hot path. Request accounting uses
atomic counters and a bounded `plugin`/`rcode` label set.

Note that the self-check duration and failure metrics *do not* have a `server` label, because being overloaded is a symptom of
the running process, *not* a specific server.

## Examples

Run another health endpoint on http://localhost:8091.

~~~ corefile
. {
    health localhost:8091
}
~~~

Set a lame duck duration of 1 second:

~~~ corefile
. {
    health localhost:8092 {
        lameduck 1s
    }
}
~~~

Remove the node from load balancing after more than 20,000 in-flight queries, 4,000 queued
requests, or 50ms average latency, and restore it after the values fall to 75% of thresholds:

~~~ corefile
. {
    health localhost:8093 {
        inflight_threshold 20000
        queue_threshold 4000
        latency_threshold 50ms
        recovery_ratio 0.75
    }
}
~~~
