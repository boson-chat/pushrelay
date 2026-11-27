// Package metrics defines the relay's Prometheus metrics, served on the
// internal listener's /metrics.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds the collectors. Use New.
type Metrics struct {
	reg              *prometheus.Registry
	pushes           *prometheus.CounterVec
	pushBytes        prometheus.Histogram
	upstream         *prometheus.CounterVec
	upstreamDuration *prometheus.HistogramVec
	mailboxes        *prometheus.GaugeVec
	mailboxOps       *prometheus.CounterVec
	attestations     *prometheus.CounterVec
	installAlerts    prometheus.Counter
	expired          prometheus.Counter
}

// New registers the collectors (plus Go/process collectors) on a fresh registry.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		reg: reg,
		pushes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pushrelay_pushes_total",
			Help: "Pushes received from installs, by outcome (accepted, or the rejection reason).",
		}, []string{"outcome"}),
		pushBytes: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "pushrelay_push_body_bytes",
			Help:    "Size of accepted push bodies.",
			Buckets: []float64{256, 512, 1024, 2048, 3072, 4096},
		}),
		upstream: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pushrelay_upstream_requests_total",
			Help: "Requests to APNs / FCM by service and result (ok, unregistered, too_large, error_<status>).",
		}, []string{"service", "result"}),
		upstreamDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "pushrelay_upstream_request_seconds",
			Help:    "APNs / FCM request latency.",
			Buckets: prometheus.DefBuckets,
		}, []string{"service"}),
		mailboxes: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "pushrelay_mailboxes",
			Help: "Mailboxes by platform.",
		}, []string{"platform"}),
		mailboxOps: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pushrelay_mailbox_operations_total",
			Help: "Mailbox create/update/delete calls by operation and outcome.",
		}, []string{"op", "outcome"}),
		attestations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pushrelay_attestations_total",
			Help: "Attestation checks by method and result.",
		}, []string{"method", "result"}),
		installAlerts: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "pushrelay_install_limit_alerts_total",
			Help: "Times an install went above its hourly push ceiling.",
		}),
		expired: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "pushrelay_mailboxes_expired_total",
			Help: "Mailboxes deleted for being unused.",
		}),
	}
	reg.MustRegister(m.pushes, m.pushBytes, m.upstream, m.upstreamDuration, m.mailboxes, m.mailboxOps,
		m.attestations, m.installAlerts, m.expired,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}

// Handler serves /metrics.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{Registry: m.reg})
}

// PushCount is the pushes counter for outcome (tests).
func (m *Metrics) PushCount(outcome string) prometheus.Counter {
	return m.pushes.WithLabelValues(outcome)
}

func (m *Metrics) Push(outcome string) { m.pushes.WithLabelValues(outcome).Inc() }
func (m *Metrics) PushBytes(n int)     { m.pushBytes.Observe(float64(n)) }
func (m *Metrics) InstallAlert()       { m.installAlerts.Inc() }
func (m *Metrics) Expired(n int64)     { m.expired.Add(float64(n)) }
func (m *Metrics) MailboxOp(op, outcome string) {
	m.mailboxOps.WithLabelValues(op, outcome).Inc()
}
func (m *Metrics) Attestation(method, result string) {
	m.attestations.WithLabelValues(method, result).Inc()
}
func (m *Metrics) Upstream(service, result string, d time.Duration) {
	m.upstream.WithLabelValues(service, result).Inc()
	m.upstreamDuration.WithLabelValues(service).Observe(d.Seconds())
}

// SetMailboxes sets the per-platform gauge (platforms missing from counts are 0).
func (m *Metrics) SetMailboxes(counts map[string]int64) {
	for _, p := range []string{"apns", "apns-sandbox", "fcm"} {
		m.mailboxes.WithLabelValues(p).Set(float64(counts[p]))
	}
}
