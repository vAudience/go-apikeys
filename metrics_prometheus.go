package apikeys

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// PrometheusMetrics implements MetricsProvider using Prometheus client library
type PrometheusMetrics struct {
	namespace string
	registry  *prometheus.Registry

	// Authentication metrics
	authAttempts *prometheus.CounterVec
	authLatency  *prometheus.HistogramVec
	authErrors   *prometheus.CounterVec

	// Operation metrics
	operationLatency *prometheus.HistogramVec
	operationErrors  *prometheus.CounterVec

	// Cache metrics
	cacheHits      prometheus.Counter
	cacheMisses    prometheus.Counter
	cacheEvictions *prometheus.CounterVec

	// Resource metrics
	activeKeys prometheus.Gauge
}

// NewPrometheusMetrics creates a new PrometheusMetrics instance with the given namespace.
// If registry is nil, the default registry will be used.
func NewPrometheusMetrics(namespace string, registry *prometheus.Registry) *PrometheusMetrics {
	if namespace == "" {
		namespace = "apikeys"
	}

	if registry == nil {
		registry = prometheus.DefaultRegisterer.(*prometheus.Registry)
	}

	factory := promauto.With(registry)

	p := &PrometheusMetrics{
		namespace: namespace,
		registry:  registry,
	}

	// Authentication metrics
	p.authAttempts = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "auth_attempts_total",
			Help:      "Total number of authentication attempts",
		},
		[]string{"outcome", "org_id", "key_type"},
	)

	p.authLatency = factory.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "auth_duration_seconds",
			Help:      "Authentication latency in seconds",
			Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
		},
		[]string{"outcome", "cache_hit"},
	)

	p.authErrors = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "auth_errors_total",
			Help:      "Total number of authentication errors by type",
		},
		[]string{"error_type", "endpoint"},
	)

	// Operation metrics
	p.operationLatency = factory.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "operation_duration_seconds",
			Help:      "Operation latency in seconds",
			Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"operation", "org_id"},
	)

	p.operationErrors = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "operation_errors_total",
			Help:      "Total number of operation errors by type",
		},
		[]string{"operation", "error_type"},
	)

	// Cache metrics
	p.cacheHits = factory.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "cache_hits_total",
			Help:      "Total number of cache hits",
		},
	)

	p.cacheMisses = factory.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "cache_misses_total",
			Help:      "Total number of cache misses",
		},
	)

	p.cacheEvictions = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "cache_evictions_total",
			Help:      "Total number of cache evictions by reason",
		},
		[]string{"reason"},
	)

	// Resource metrics
	p.activeKeys = factory.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "active_keys",
			Help:      "Current number of active API keys",
		},
	)

	return p
}

// RecordAuthAttempt records an authentication attempt with outcome and latency
func (p *PrometheusMetrics) RecordAuthAttempt(ctx context.Context, success bool, latency time.Duration, labels map[string]string) {
	outcome := "failure"
	if success {
		outcome = "success"
	}

	orgID := labels["org_id"]
	if orgID == "" {
		orgID = "unknown"
	}

	keyType := labels["key_type"]
	if keyType == "" {
		keyType = "standard"
	}

	cacheHit := labels["cache_hit"]
	if cacheHit == "" {
		cacheHit = "false"
	}

	p.authAttempts.WithLabelValues(outcome, orgID, keyType).Inc()
	p.authLatency.WithLabelValues(outcome, cacheHit).Observe(latency.Seconds())
}

// RecordAuthError records an authentication error by type
func (p *PrometheusMetrics) RecordAuthError(ctx context.Context, errorType string, labels map[string]string) {
	endpoint := labels["endpoint"]
	if endpoint == "" {
		endpoint = "unknown"
	}

	p.authErrors.WithLabelValues(errorType, endpoint).Inc()
}

// RecordOperation records a service operation with latency
func (p *PrometheusMetrics) RecordOperation(ctx context.Context, operation string, latency time.Duration, labels map[string]string) {
	orgID := labels["org_id"]
	if orgID == "" {
		orgID = "unknown"
	}

	p.operationLatency.WithLabelValues(operation, orgID).Observe(latency.Seconds())
}

// RecordOperationError records a service operation error
func (p *PrometheusMetrics) RecordOperationError(ctx context.Context, operation string, errorType string) {
	p.operationErrors.WithLabelValues(operation, errorType).Inc()
}

// RecordCacheHit records a cache hit event
func (p *PrometheusMetrics) RecordCacheHit(ctx context.Context, key string) {
	p.cacheHits.Inc()
}

// RecordCacheMiss records a cache miss event
func (p *PrometheusMetrics) RecordCacheMiss(ctx context.Context, key string) {
	p.cacheMisses.Inc()
}

// RecordCacheEviction records a cache eviction event
func (p *PrometheusMetrics) RecordCacheEviction(ctx context.Context, reason string) {
	if reason == "" {
		reason = "unknown"
	}
	p.cacheEvictions.WithLabelValues(reason).Inc()
}

// RecordActiveKeys records the current count of active API keys
func (p *PrometheusMetrics) RecordActiveKeys(ctx context.Context, count int64) {
	p.activeKeys.Set(float64(count))
}

// Handler returns an HTTP handler for the /metrics endpoint
func (p *PrometheusMetrics) Handler() http.Handler {
	return promhttp.HandlerFor(p.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
}

// Registry returns the underlying Prometheus registry
func (p *PrometheusMetrics) Registry() *prometheus.Registry {
	return p.registry
}
