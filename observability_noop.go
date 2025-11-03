package apikeys

import (
	"context"
	"time"
)

// NoOpMetricsProvider is a no-op implementation of MetricsProvider.
// It does nothing and has zero performance overhead.
type NoOpMetricsProvider struct{}

// RecordAuthAttempt does nothing
func (n *NoOpMetricsProvider) RecordAuthAttempt(ctx context.Context, success bool, latency time.Duration, labels map[string]string) {
}

// RecordAuthError does nothing
func (n *NoOpMetricsProvider) RecordAuthError(ctx context.Context, errorType string, labels map[string]string) {
}

// RecordOperation does nothing
func (n *NoOpMetricsProvider) RecordOperation(ctx context.Context, operation string, latency time.Duration, labels map[string]string) {
}

// RecordOperationError does nothing
func (n *NoOpMetricsProvider) RecordOperationError(ctx context.Context, operation string, errorType string) {
}

// RecordCacheHit does nothing
func (n *NoOpMetricsProvider) RecordCacheHit(ctx context.Context, key string) {
}

// RecordCacheMiss does nothing
func (n *NoOpMetricsProvider) RecordCacheMiss(ctx context.Context, key string) {
}

// RecordCacheEviction does nothing
func (n *NoOpMetricsProvider) RecordCacheEviction(ctx context.Context, reason string) {
}

// RecordActiveKeys does nothing
func (n *NoOpMetricsProvider) RecordActiveKeys(ctx context.Context, count int64) {
}

// NoOpAuditProvider is a no-op implementation of AuditProvider.
// It does nothing and has zero performance overhead.
type NoOpAuditProvider struct{}

// LogAuthAttempt does nothing
func (n *NoOpAuditProvider) LogAuthAttempt(ctx context.Context, event *AuthAttemptEvent) error {
	return nil
}

// LogKeyCreated does nothing
func (n *NoOpAuditProvider) LogKeyCreated(ctx context.Context, event *KeyLifecycleEvent) error {
	return nil
}

// LogKeyUpdated does nothing
func (n *NoOpAuditProvider) LogKeyUpdated(ctx context.Context, event *KeyLifecycleEvent) error {
	return nil
}

// LogKeyDeleted does nothing
func (n *NoOpAuditProvider) LogKeyDeleted(ctx context.Context, event *KeyLifecycleEvent) error {
	return nil
}

// LogKeyAccessed does nothing
func (n *NoOpAuditProvider) LogKeyAccessed(ctx context.Context, event *KeyAccessEvent) error {
	return nil
}

// LogSecurityEvent does nothing
func (n *NoOpAuditProvider) LogSecurityEvent(ctx context.Context, event *SecurityEvent) error {
	return nil
}

// NoOpTracingProvider is a no-op implementation of TracingProvider.
// It does nothing and has zero performance overhead.
type NoOpTracingProvider struct{}

// StartSpan returns the context unchanged and a no-op span
func (n *NoOpTracingProvider) StartSpan(ctx context.Context, operation string) (context.Context, Span) {
	return ctx, &NoOpSpan{}
}

// ExtractTraceContext returns an empty trace context
func (n *NoOpTracingProvider) ExtractTraceContext(ctx context.Context) TraceContext {
	return TraceContext{}
}

// InjectTraceContext does nothing
func (n *NoOpTracingProvider) InjectTraceContext(ctx context.Context, carrier interface{}) error {
	return nil
}

// NoOpSpan is a no-op implementation of Span
type NoOpSpan struct{}

// SetAttribute does nothing
func (n *NoOpSpan) SetAttribute(key string, value interface{}) {
}

// RecordError does nothing
func (n *NoOpSpan) RecordError(err error) {
}

// End does nothing
func (n *NoOpSpan) End() {
}
