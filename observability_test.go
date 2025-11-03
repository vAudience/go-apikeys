package apikeys

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewObservability(t *testing.T) {
	t.Run("creates observability with all providers", func(t *testing.T) {
		metrics := newMockMetricsProvider()
		audit := newMockAuditProvider()
		tracing := &NoOpTracingProvider{}

		obs := NewObservability(metrics, audit, tracing)

		require.NotNil(t, obs)
		assert.Equal(t, metrics, obs.Metrics)
		assert.Equal(t, audit, obs.Audit)
		assert.Equal(t, tracing, obs.Tracing)
	})

	t.Run("replaces nil providers with no-ops", func(t *testing.T) {
		obs := NewObservability(nil, nil, nil)

		require.NotNil(t, obs)
		assert.IsType(t, &NoOpMetricsProvider{}, obs.Metrics)
		assert.IsType(t, &NoOpAuditProvider{}, obs.Audit)
		assert.IsType(t, &NoOpTracingProvider{}, obs.Tracing)
	})

	t.Run("mixes real and nil providers", func(t *testing.T) {
		metrics := newMockMetricsProvider()

		obs := NewObservability(metrics, nil, nil)

		require.NotNil(t, obs)
		assert.Equal(t, metrics, obs.Metrics)
		assert.IsType(t, &NoOpAuditProvider{}, obs.Audit)
		assert.IsType(t, &NoOpTracingProvider{}, obs.Tracing)
	})
}

func TestObservability_MetricsProvider(t *testing.T) {
	ctx := context.Background()

	t.Run("metrics provider records auth attempts", func(t *testing.T) {
		metrics := newMockMetricsProvider()
		obs := NewObservability(metrics, nil, nil)

		// Record successful auth
		obs.Metrics.RecordAuthAttempt(ctx, true, 10*time.Millisecond, map[string]string{
			"org_id": "test-org",
		})

		assert.Equal(t, 1, metrics.GetAuthAttemptCount())
		assert.Equal(t, 1, metrics.GetAuthSuccessCount())
		assert.Equal(t, 0, metrics.GetAuthFailureCount())
	})

	t.Run("metrics provider records auth failures", func(t *testing.T) {
		metrics := newMockMetricsProvider()
		obs := NewObservability(metrics, nil, nil)

		// Record failed auth
		obs.Metrics.RecordAuthAttempt(ctx, false, 5*time.Millisecond, map[string]string{
			"org_id": "test-org",
		})

		assert.Equal(t, 1, metrics.GetAuthAttemptCount())
		assert.Equal(t, 0, metrics.GetAuthSuccessCount())
		assert.Equal(t, 1, metrics.GetAuthFailureCount())
	})

	t.Run("metrics provider records operations", func(t *testing.T) {
		metrics := newMockMetricsProvider()
		obs := NewObservability(metrics, nil, nil)

		// Record operation
		obs.Metrics.RecordOperation(ctx, "create_key", 20*time.Millisecond, map[string]string{
			"org_id": "test-org",
		})

		assert.Equal(t, 1, metrics.GetOperationCount("create_key"))
		assert.Equal(t, 0, metrics.GetOperationCount("delete_key"))
	})

	t.Run("metrics provider records cache hits and misses", func(t *testing.T) {
		metrics := newMockMetricsProvider()
		obs := NewObservability(metrics, nil, nil)

		// Record cache events
		obs.Metrics.RecordCacheHit(ctx, "key1")
		obs.Metrics.RecordCacheHit(ctx, "key2")
		obs.Metrics.RecordCacheMiss(ctx, "key3")

		assert.Equal(t, 2, metrics.GetCacheHitCount())
		assert.Equal(t, 1, metrics.GetCacheMissCount())
	})
}

func TestObservability_AuditProvider(t *testing.T) {
	ctx := context.Background()

	t.Run("audit provider logs auth attempts", func(t *testing.T) {
		audit := newMockAuditProvider()
		obs := NewObservability(nil, audit, nil)

		event := &AuthAttemptEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeAuthSuccess,
				ActorInfo{UserID: "user1", OrgID: "org1"},
				ResourceInfo{Type: "endpoint", ID: "/api/users"},
				OutcomeSuccess,
			),
			Method:      "api_key",
			KeyProvided: true,
			KeyValid:    true,
		}

		err := obs.Audit.LogAuthAttempt(ctx, event)

		require.NoError(t, err)
		assert.Equal(t, 1, audit.GetAuthEventCount())
		assert.Equal(t, 1, audit.GetAuthSuccessCount())
	})

	t.Run("audit provider logs key lifecycle events", func(t *testing.T) {
		audit := newMockAuditProvider()
		obs := NewObservability(nil, audit, nil)

		// Log key created
		createEvent := &KeyLifecycleEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeKeyCreated,
				ActorInfo{UserID: "admin1"},
				ResourceInfo{Type: "api_key", ID: "key-hash"},
				OutcomeSuccess,
			),
			Operation:    "create",
			TargetUserID: "user1",
		}
		err := obs.Audit.LogKeyCreated(ctx, createEvent)
		require.NoError(t, err)

		// Log key updated
		updateEvent := &KeyLifecycleEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeKeyUpdated,
				ActorInfo{UserID: "admin1"},
				ResourceInfo{Type: "api_key", ID: "key-hash"},
				OutcomeSuccess,
			),
			Operation:    "update",
			TargetUserID: "user1",
		}
		err = obs.Audit.LogKeyUpdated(ctx, updateEvent)
		require.NoError(t, err)

		// Log key deleted
		deleteEvent := &KeyLifecycleEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeKeyDeleted,
				ActorInfo{UserID: "admin1"},
				ResourceInfo{Type: "api_key", ID: "key-hash"},
				OutcomeSuccess,
			),
			Operation:    "delete",
			TargetUserID: "user1",
		}
		err = obs.Audit.LogKeyDeleted(ctx, deleteEvent)
		require.NoError(t, err)

		assert.Equal(t, 1, audit.GetKeyCreatedCount())
		assert.Equal(t, 1, audit.GetKeyUpdatedCount())
		assert.Equal(t, 1, audit.GetKeyDeletedCount())
	})

	t.Run("audit provider logs security events", func(t *testing.T) {
		audit := newMockAuditProvider()
		obs := NewObservability(nil, audit, nil)

		event := &SecurityEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeSecurityThreat,
				ActorInfo{IPAddress: "192.168.1.1"},
				ResourceInfo{Type: "endpoint", ID: "/api/users"},
				OutcomeBlocked,
			),
			ThreatType: ThreatTypeBruteForce,
			Severity:   SeverityHigh,
			Details:    "Multiple failed login attempts",
		}

		err := obs.Audit.LogSecurityEvent(ctx, event)

		require.NoError(t, err)
		assert.Equal(t, 1, audit.GetSecurityEventCount())
	})
}

func TestObservability_ConcurrentAccess(t *testing.T) {
	metrics := newMockMetricsProvider()
	audit := newMockAuditProvider()
	obs := NewObservability(metrics, audit, nil)

	ctx := context.Background()
	iterations := 100

	// Test concurrent metrics recording
	t.Run("concurrent metrics recording is thread-safe", func(t *testing.T) {
		metrics.Reset()

		done := make(chan bool)
		for i := 0; i < iterations; i++ {
			go func() {
				obs.Metrics.RecordAuthAttempt(ctx, true, time.Millisecond, nil)
				done <- true
			}()
		}

		// Wait for all goroutines
		for i := 0; i < iterations; i++ {
			<-done
		}

		assert.Equal(t, iterations, metrics.GetAuthAttemptCount())
	})

	// Test concurrent audit logging
	t.Run("concurrent audit logging is thread-safe", func(t *testing.T) {
		audit.Reset()

		done := make(chan bool)
		for i := 0; i < iterations; i++ {
			go func() {
				event := &AuthAttemptEvent{
					BaseAuditEvent: NewBaseAuditEvent(
						EventTypeAuthSuccess,
						ActorInfo{},
						ResourceInfo{},
						OutcomeSuccess,
					),
				}
				obs.Audit.LogAuthAttempt(ctx, event)
				done <- true
			}()
		}

		// Wait for all goroutines
		for i := 0; i < iterations; i++ {
			<-done
		}

		assert.Equal(t, iterations, audit.GetAuthEventCount())
	})
}

func TestObservability_NilContextHandling(t *testing.T) {
	metrics := newMockMetricsProvider()
	audit := newMockAuditProvider()
	obs := NewObservability(metrics, audit, nil)

	t.Run("metrics provider handles nil context", func(t *testing.T) {
		// Should not panic
		assert.NotPanics(t, func() {
			obs.Metrics.RecordAuthAttempt(nil, true, time.Millisecond, nil)
		})
	})

	t.Run("audit provider handles nil context", func(t *testing.T) {
		event := &AuthAttemptEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeAuthSuccess,
				ActorInfo{},
				ResourceInfo{},
				OutcomeSuccess,
			),
		}

		// Should not panic
		assert.NotPanics(t, func() {
			obs.Audit.LogAuthAttempt(nil, event)
		})
	})
}
