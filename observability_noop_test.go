package apikeys

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNoOpMetricsProvider(t *testing.T) {
	provider := &NoOpMetricsProvider{}
	ctx := context.Background()

	t.Run("RecordAuthAttempt does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			provider.RecordAuthAttempt(ctx, true, time.Millisecond, nil)
			provider.RecordAuthAttempt(ctx, false, time.Millisecond, map[string]string{"org_id": "test"})
			provider.RecordAuthAttempt(nil, true, 0, nil)
		})
	})

	t.Run("RecordAuthError does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			provider.RecordAuthError(ctx, "key_not_found", nil)
			provider.RecordAuthError(ctx, "key_invalid", map[string]string{"endpoint": "/api"})
			provider.RecordAuthError(nil, "", nil)
		})
	})

	t.Run("RecordOperation does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			provider.RecordOperation(ctx, "create_key", time.Millisecond, nil)
			provider.RecordOperation(ctx, "delete_key", time.Second, map[string]string{"org_id": "test"})
			provider.RecordOperation(nil, "", 0, nil)
		})
	})

	t.Run("RecordOperationError does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			provider.RecordOperationError(ctx, "create_key", "validation_error")
			provider.RecordOperationError(nil, "", "")
		})
	})

	t.Run("RecordCacheHit does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			provider.RecordCacheHit(ctx, "key1")
			provider.RecordCacheHit(nil, "")
		})
	})

	t.Run("RecordCacheMiss does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			provider.RecordCacheMiss(ctx, "key1")
			provider.RecordCacheMiss(nil, "")
		})
	})

	t.Run("RecordCacheEviction does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			provider.RecordCacheEviction(ctx, "size")
			provider.RecordCacheEviction(nil, "")
		})
	})

	t.Run("RecordActiveKeys does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			provider.RecordActiveKeys(ctx, 100)
			provider.RecordActiveKeys(nil, 0)
			provider.RecordActiveKeys(ctx, -1)
		})
	})

	t.Run("concurrent calls are safe", func(t *testing.T) {
		done := make(chan bool)
		iterations := 100

		for i := 0; i < iterations; i++ {
			go func() {
				provider.RecordAuthAttempt(ctx, true, time.Millisecond, nil)
				provider.RecordOperation(ctx, "test", time.Millisecond, nil)
				provider.RecordCacheHit(ctx, "key")
				done <- true
			}()
		}

		for i := 0; i < iterations; i++ {
			<-done
		}
	})
}

func TestNoOpAuditProvider(t *testing.T) {
	provider := &NoOpAuditProvider{}
	ctx := context.Background()

	t.Run("LogAuthAttempt does not panic", func(t *testing.T) {
		event := &AuthAttemptEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeAuthSuccess,
				ActorInfo{UserID: "user1"},
				ResourceInfo{Type: "endpoint"},
				OutcomeSuccess,
			),
		}

		assert.NotPanics(t, func() {
			err := provider.LogAuthAttempt(ctx, event)
			assert.NoError(t, err)
		})

		assert.NotPanics(t, func() {
			err := provider.LogAuthAttempt(nil, nil)
			assert.NoError(t, err)
		})
	})

	t.Run("LogKeyCreated does not panic", func(t *testing.T) {
		event := &KeyLifecycleEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeKeyCreated,
				ActorInfo{UserID: "admin1"},
				ResourceInfo{Type: "api_key"},
				OutcomeSuccess,
			),
		}

		assert.NotPanics(t, func() {
			err := provider.LogKeyCreated(ctx, event)
			assert.NoError(t, err)
		})

		assert.NotPanics(t, func() {
			err := provider.LogKeyCreated(nil, nil)
			assert.NoError(t, err)
		})
	})

	t.Run("LogKeyUpdated does not panic", func(t *testing.T) {
		event := &KeyLifecycleEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeKeyUpdated,
				ActorInfo{UserID: "admin1"},
				ResourceInfo{Type: "api_key"},
				OutcomeSuccess,
			),
		}

		assert.NotPanics(t, func() {
			err := provider.LogKeyUpdated(ctx, event)
			assert.NoError(t, err)
		})
	})

	t.Run("LogKeyDeleted does not panic", func(t *testing.T) {
		event := &KeyLifecycleEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeKeyDeleted,
				ActorInfo{UserID: "admin1"},
				ResourceInfo{Type: "api_key"},
				OutcomeSuccess,
			),
		}

		assert.NotPanics(t, func() {
			err := provider.LogKeyDeleted(ctx, event)
			assert.NoError(t, err)
		})
	})

	t.Run("LogKeyAccessed does not panic", func(t *testing.T) {
		event := &KeyAccessEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeKeyAccessed,
				ActorInfo{UserID: "user1"},
				ResourceInfo{Type: "endpoint"},
				OutcomeSuccess,
			),
		}

		assert.NotPanics(t, func() {
			err := provider.LogKeyAccessed(ctx, event)
			assert.NoError(t, err)
		})
	})

	t.Run("LogSecurityEvent does not panic", func(t *testing.T) {
		event := &SecurityEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeSecurityThreat,
				ActorInfo{IPAddress: "192.168.1.1"},
				ResourceInfo{Type: "endpoint"},
				OutcomeBlocked,
			),
			ThreatType: ThreatTypeBruteForce,
			Severity:   SeverityHigh,
		}

		assert.NotPanics(t, func() {
			err := provider.LogSecurityEvent(ctx, event)
			assert.NoError(t, err)
		})
	})

	t.Run("concurrent calls are safe", func(t *testing.T) {
		done := make(chan bool)
		iterations := 100

		event := &AuthAttemptEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeAuthSuccess,
				ActorInfo{},
				ResourceInfo{},
				OutcomeSuccess,
			),
		}

		for i := 0; i < iterations; i++ {
			go func() {
				provider.LogAuthAttempt(ctx, event)
				provider.LogKeyCreated(ctx, &KeyLifecycleEvent{})
				provider.LogSecurityEvent(ctx, &SecurityEvent{})
				done <- true
			}()
		}

		for i := 0; i < iterations; i++ {
			<-done
		}
	})
}

func TestNoOpTracingProvider(t *testing.T) {
	provider := &NoOpTracingProvider{}
	ctx := context.Background()

	t.Run("StartSpan does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			newCtx, span := provider.StartSpan(ctx, "test_operation")
			assert.NotNil(t, newCtx)
			assert.NotNil(t, span)
		})

		assert.NotPanics(t, func() {
			newCtx, span := provider.StartSpan(nil, "")
			assert.NotNil(t, span)
			_ = newCtx
		})
	})

	t.Run("ExtractTraceContext does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			traceCtx := provider.ExtractTraceContext(ctx)
			assert.Equal(t, "", traceCtx.TraceID)
			assert.Equal(t, "", traceCtx.SpanID)
		})

		assert.NotPanics(t, func() {
			_ = provider.ExtractTraceContext(nil)
		})
	})

	t.Run("InjectTraceContext does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			err := provider.InjectTraceContext(ctx, nil)
			assert.NoError(t, err)
		})

		assert.NotPanics(t, func() {
			err := provider.InjectTraceContext(nil, map[string]string{})
			assert.NoError(t, err)
		})
	})

	t.Run("concurrent calls are safe", func(t *testing.T) {
		done := make(chan bool)
		iterations := 100

		for i := 0; i < iterations; i++ {
			go func() {
				_, span := provider.StartSpan(ctx, "test")
				provider.ExtractTraceContext(ctx)
				provider.InjectTraceContext(ctx, nil)
				span.End()
				done <- true
			}()
		}

		for i := 0; i < iterations; i++ {
			<-done
		}
	})
}

func TestNoOpSpan(t *testing.T) {
	span := &NoOpSpan{}

	t.Run("SetAttribute does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			span.SetAttribute("key", "value")
			span.SetAttribute("", nil)
			span.SetAttribute("key", 123)
			span.SetAttribute("key", true)
		})
	})

	t.Run("RecordError does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			span.RecordError(ErrUnauthorized)
			span.RecordError(nil)
		})
	})

	t.Run("End does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			span.End()
			span.End() // Can call multiple times
		})
	})

	t.Run("concurrent calls are safe", func(t *testing.T) {
		done := make(chan bool)
		iterations := 100

		for i := 0; i < iterations; i++ {
			go func() {
				span.SetAttribute("key", "value")
				span.RecordError(nil)
				span.End()
				done <- true
			}()
		}

		for i := 0; i < iterations; i++ {
			<-done
		}
	})
}

func BenchmarkNoOpMetricsProvider(b *testing.B) {
	provider := &NoOpMetricsProvider{}
	ctx := context.Background()
	labels := map[string]string{"org_id": "test"}

	b.Run("RecordAuthAttempt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			provider.RecordAuthAttempt(ctx, true, time.Millisecond, labels)
		}
	})

	b.Run("RecordOperation", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			provider.RecordOperation(ctx, "create_key", time.Millisecond, labels)
		}
	})

	b.Run("RecordCacheHit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			provider.RecordCacheHit(ctx, "key")
		}
	})
}

func BenchmarkNoOpAuditProvider(b *testing.B) {
	provider := &NoOpAuditProvider{}
	ctx := context.Background()
	event := &AuthAttemptEvent{
		BaseAuditEvent: NewBaseAuditEvent(
			EventTypeAuthSuccess,
			ActorInfo{UserID: "user1"},
			ResourceInfo{Type: "endpoint"},
			OutcomeSuccess,
		),
	}

	b.Run("LogAuthAttempt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			provider.LogAuthAttempt(ctx, event)
		}
	})
}

func BenchmarkNoOpTracingProvider(b *testing.B) {
	provider := &NoOpTracingProvider{}
	ctx := context.Background()

	b.Run("StartSpan", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, span := provider.StartSpan(ctx, "test")
			span.End()
		}
	})

	b.Run("ExtractTraceContext", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			provider.ExtractTraceContext(ctx)
		}
	})
}
