package apikeys

import (
	"context"
	"time"
)

// Observability provides a centralized access point for all observability features
// including metrics, audit logging, and tracing.
type Observability struct {
	Metrics MetricsProvider
	Audit   AuditProvider
	Tracing TracingProvider
}

// MetricsProvider defines the interface for recording operational metrics.
// Implementations can integrate with Prometheus, OpenTelemetry, or custom backends.
type MetricsProvider interface {
	// RecordAuthAttempt records an authentication attempt with outcome and latency
	RecordAuthAttempt(ctx context.Context, success bool, latency time.Duration, labels map[string]string)

	// RecordAuthError records an authentication error by type
	RecordAuthError(ctx context.Context, errorType string, labels map[string]string)

	// RecordOperation records a service operation with latency
	RecordOperation(ctx context.Context, operation string, latency time.Duration, labels map[string]string)

	// RecordOperationError records a service operation error
	RecordOperationError(ctx context.Context, operation string, errorType string)

	// RecordCacheHit records a cache hit event
	RecordCacheHit(ctx context.Context, key string)

	// RecordCacheMiss records a cache miss event
	RecordCacheMiss(ctx context.Context, key string)

	// RecordCacheEviction records a cache eviction event
	RecordCacheEviction(ctx context.Context, reason string)

	// RecordActiveKeys records the current count of active API keys
	RecordActiveKeys(ctx context.Context, count int64)
}

// AuditProvider defines the interface for audit logging.
// Implementations should ensure audit logs are immutable, tamper-evident,
// and retained according to compliance requirements.
type AuditProvider interface {
	// LogAuthAttempt logs an authentication attempt event
	LogAuthAttempt(ctx context.Context, event *AuthAttemptEvent) error

	// LogKeyCreated logs an API key creation event
	LogKeyCreated(ctx context.Context, event *KeyLifecycleEvent) error

	// LogKeyUpdated logs an API key update event
	LogKeyUpdated(ctx context.Context, event *KeyLifecycleEvent) error

	// LogKeyDeleted logs an API key deletion event
	LogKeyDeleted(ctx context.Context, event *KeyLifecycleEvent) error

	// LogKeyAccessed logs an API key access/usage event
	LogKeyAccessed(ctx context.Context, event *KeyAccessEvent) error

	// LogSecurityEvent logs a security-related event (suspicious activity, attacks, etc.)
	LogSecurityEvent(ctx context.Context, event *SecurityEvent) error
}

// TracingProvider defines the interface for distributed tracing.
// Implementations can integrate with OpenTelemetry, Jaeger, or custom backends.
type TracingProvider interface {
	// StartSpan starts a new span for the given operation
	StartSpan(ctx context.Context, operation string) (context.Context, Span)

	// ExtractTraceContext extracts trace context from the provided context
	ExtractTraceContext(ctx context.Context) TraceContext

	// InjectTraceContext injects trace context into a carrier (e.g., HTTP headers)
	InjectTraceContext(ctx context.Context, carrier interface{}) error
}

// Span represents a distributed tracing span
type Span interface {
	// SetAttribute sets an attribute on the span
	SetAttribute(key string, value interface{})

	// RecordError records an error that occurred during the span
	RecordError(err error)

	// End completes the span
	End()
}

// TraceContext represents distributed tracing context
type TraceContext struct {
	TraceID string
	SpanID  string
	Flags   byte
}

// NewObservability creates a new Observability instance with the provided providers.
// If any provider is nil, a no-op implementation will be used.
func NewObservability(metrics MetricsProvider, audit AuditProvider, tracing TracingProvider) *Observability {
	if metrics == nil {
		metrics = &NoOpMetricsProvider{}
	}
	if audit == nil {
		audit = &NoOpAuditProvider{}
	}
	if tracing == nil {
		tracing = &NoOpTracingProvider{}
	}

	return &Observability{
		Metrics: metrics,
		Audit:   audit,
		Tracing: tracing,
	}
}
