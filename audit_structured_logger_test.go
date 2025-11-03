package apikeys

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestNewStructuredAuditLogger(t *testing.T) {
	t.Run("creates logger with valid parameters", func(t *testing.T) {
		logger := zap.NewNop()
		auditLogger := NewStructuredAuditLogger(logger, 0.5, true)

		require.NotNil(t, auditLogger)
		assert.Equal(t, logger, auditLogger.logger)
		assert.Equal(t, 0.5, auditLogger.sampleRate)
		assert.True(t, auditLogger.auditSuccess)
	})

	t.Run("handles nil logger by creating nop", func(t *testing.T) {
		auditLogger := NewStructuredAuditLogger(nil, 1.0, false)

		require.NotNil(t, auditLogger)
		assert.NotNil(t, auditLogger.logger)
		assert.Equal(t, 1.0, auditLogger.sampleRate)
		assert.False(t, auditLogger.auditSuccess)
	})

	t.Run("clamps negative sample rate to 1.0", func(t *testing.T) {
		auditLogger := NewStructuredAuditLogger(nil, -0.5, true)

		assert.Equal(t, 1.0, auditLogger.sampleRate)
	})

	t.Run("clamps sample rate > 1.0 to 1.0", func(t *testing.T) {
		auditLogger := NewStructuredAuditLogger(nil, 1.5, true)

		assert.Equal(t, 1.0, auditLogger.sampleRate)
	})

	t.Run("accepts sample rate boundaries", func(t *testing.T) {
		logger1 := NewStructuredAuditLogger(nil, 0.0, true)
		assert.Equal(t, 0.0, logger1.sampleRate)

		logger2 := NewStructuredAuditLogger(nil, 1.0, true)
		assert.Equal(t, 1.0, logger2.sampleRate)
	})
}

func TestStructuredAuditLogger_shouldSample(t *testing.T) {
	t.Run("100% sample rate always returns true", func(t *testing.T) {
		logger := NewStructuredAuditLogger(nil, 1.0, true)

		for i := 0; i < 100; i++ {
			assert.True(t, logger.shouldSample(), "iteration %d should sample", i)
		}
	})

	t.Run("0% sample rate never returns true", func(t *testing.T) {
		logger := NewStructuredAuditLogger(nil, 0.0, true)

		for i := 0; i < 100; i++ {
			assert.False(t, logger.shouldSample(), "iteration %d should not sample", i)
		}
	})

	t.Run("50% sample rate approximately half true", func(t *testing.T) {
		logger := NewStructuredAuditLogger(nil, 0.5, true)

		trueCount := 0
		iterations := 10000 // Large sample for statistical accuracy

		for i := 0; i < iterations; i++ {
			if logger.shouldSample() {
				trueCount++
			}
		}

		// Allow 5% deviation from expected 50%
		expectedMin := int(float64(iterations) * 0.45)
		expectedMax := int(float64(iterations) * 0.55)

		assert.GreaterOrEqual(t, trueCount, expectedMin, "sample rate too low")
		assert.LessOrEqual(t, trueCount, expectedMax, "sample rate too high")
	})
}

func TestStructuredAuditLogger_LogAuthAttempt(t *testing.T) {
	ctx := context.Background()

	t.Run("logs auth failure always (no sampling)", func(t *testing.T) {
		core, logs := observer.New(zapcore.InfoLevel)
		zapLogger := zap.New(core)
		logger := NewStructuredAuditLogger(zapLogger, 0.0, false) // 0% sample rate

		event := &AuthAttemptEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeAuthFailure,
				ActorInfo{UserID: "user1"},
				ResourceInfo{Type: "endpoint"},
				OutcomeFailure,
			),
		}

		err := logger.LogAuthAttempt(ctx, event)

		require.NoError(t, err)
		assert.Equal(t, 1, logs.Len(), "failure should be logged even with 0% sample rate")
	})

	t.Run("logs blocked auth always (no sampling)", func(t *testing.T) {
		core, logs := observer.New(zapcore.InfoLevel)
		zapLogger := zap.New(core)
		logger := NewStructuredAuditLogger(zapLogger, 0.0, false)

		event := &AuthAttemptEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeAuthFailure,
				ActorInfo{IPAddress: "192.168.1.1"},
				ResourceInfo{Type: "endpoint"},
				OutcomeBlocked,
			),
		}

		err := logger.LogAuthAttempt(ctx, event)

		require.NoError(t, err)
		assert.Equal(t, 1, logs.Len(), "blocked should be logged even with 0% sample rate")
	})

	t.Run("skips success when auditSuccess disabled", func(t *testing.T) {
		core, logs := observer.New(zapcore.InfoLevel)
		zapLogger := zap.New(core)
		logger := NewStructuredAuditLogger(zapLogger, 1.0, false) // auditSuccess = false

		event := &AuthAttemptEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeAuthSuccess,
				ActorInfo{UserID: "user1"},
				ResourceInfo{Type: "endpoint"},
				OutcomeSuccess,
			),
		}

		err := logger.LogAuthAttempt(ctx, event)

		require.NoError(t, err)
		assert.Equal(t, 0, logs.Len(), "success should not be logged when auditSuccess=false")
	})

	t.Run("logs success when auditSuccess enabled and sample rate 100%", func(t *testing.T) {
		core, logs := observer.New(zapcore.InfoLevel)
		zapLogger := zap.New(core)
		logger := NewStructuredAuditLogger(zapLogger, 1.0, true)

		event := &AuthAttemptEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeAuthSuccess,
				ActorInfo{UserID: "user1"},
				ResourceInfo{Type: "endpoint"},
				OutcomeSuccess,
			),
			Method:   "api_key",
			KeyValid: true,
		}

		err := logger.LogAuthAttempt(ctx, event)

		require.NoError(t, err)
		assert.Equal(t, 1, logs.Len(), "success should be logged when auditSuccess=true")

		// Verify log structure
		logEntry := logs.All()[0]
		assert.Equal(t, zapcore.InfoLevel, logEntry.Level)
		assert.Equal(t, "AUDIT_EVENT", logEntry.Message)

		// Verify event_type field
		eventTypeField := logEntry.ContextMap()["event_type"]
		assert.Equal(t, EventTypeAuthSuccess, eventTypeField)
	})

	t.Run("skips success based on sample rate", func(t *testing.T) {
		core, logs := observer.New(zapcore.InfoLevel)
		zapLogger := zap.New(core)
		logger := NewStructuredAuditLogger(zapLogger, 0.0, true) // 0% sample rate

		event := &AuthAttemptEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeAuthSuccess,
				ActorInfo{UserID: "user1"},
				ResourceInfo{Type: "endpoint"},
				OutcomeSuccess,
			),
		}

		err := logger.LogAuthAttempt(ctx, event)

		require.NoError(t, err)
		assert.Equal(t, 0, logs.Len(), "success should not be logged with 0% sample rate")
	})

	t.Run("handles nil event gracefully", func(t *testing.T) {
		core, logs := observer.New(zapcore.InfoLevel)
		zapLogger := zap.New(core)
		logger := NewStructuredAuditLogger(zapLogger, 1.0, true)

		err := logger.LogAuthAttempt(ctx, nil)

		require.NoError(t, err)
		assert.Equal(t, 0, logs.Len(), "nil event should not log")
	})

	t.Run("marshals event to JSON", func(t *testing.T) {
		core, logs := observer.New(zapcore.InfoLevel)
		zapLogger := zap.New(core)
		logger := NewStructuredAuditLogger(zapLogger, 1.0, true)

		event := &AuthAttemptEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeAuthSuccess,
				ActorInfo{UserID: "test-user", OrgID: "test-org"},
				ResourceInfo{Type: "endpoint", ID: "/api/test"},
				OutcomeSuccess,
			),
			Method:      "api_key",
			KeyProvided: true,
			KeyValid:    true,
		}

		err := logger.LogAuthAttempt(ctx, event)

		require.NoError(t, err)
		require.Equal(t, 1, logs.Len())

		// Verify JSON structure
		logEntry := logs.All()[0]
		eventJSONField := logEntry.ContextMap()["event"]
		require.NotNil(t, eventJSONField)

		// Unmarshal to verify it's valid JSON
		var unmarshaled AuthAttemptEvent
		err = json.Unmarshal([]byte(eventJSONField.(string)), &unmarshaled)
		require.NoError(t, err)

		assert.Equal(t, "test-user", unmarshaled.Actor.UserID)
		assert.Equal(t, "test-org", unmarshaled.Actor.OrgID)
		assert.Equal(t, "api_key", unmarshaled.Method)
	})
}

func TestStructuredAuditLogger_LogKeyCreated(t *testing.T) {
	ctx := context.Background()

	t.Run("logs key creation event", func(t *testing.T) {
		core, logs := observer.New(zapcore.InfoLevel)
		zapLogger := zap.New(core)
		logger := NewStructuredAuditLogger(zapLogger, 1.0, true)

		event := &KeyLifecycleEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeKeyCreated,
				ActorInfo{UserID: "admin1"},
				ResourceInfo{Type: "api_key", ID: "key-hash-123"},
				OutcomeSuccess,
			),
			Operation:    "create",
			TargetUserID: "user1",
		}

		err := logger.LogKeyCreated(ctx, event)

		require.NoError(t, err)
		assert.Equal(t, 1, logs.Len())

		logEntry := logs.All()[0]
		assert.Equal(t, zapcore.InfoLevel, logEntry.Level)
		assert.Equal(t, "AUDIT_EVENT", logEntry.Message)
		assert.Equal(t, EventTypeKeyCreated, logEntry.ContextMap()["event_type"])
	})

	t.Run("handles nil event gracefully", func(t *testing.T) {
		core, logs := observer.New(zapcore.InfoLevel)
		zapLogger := zap.New(core)
		logger := NewStructuredAuditLogger(zapLogger, 1.0, true)

		err := logger.LogKeyCreated(ctx, nil)

		require.NoError(t, err)
		assert.Equal(t, 0, logs.Len())
	})
}

func TestStructuredAuditLogger_LogKeyUpdated(t *testing.T) {
	ctx := context.Background()

	t.Run("logs key update event", func(t *testing.T) {
		core, logs := observer.New(zapcore.InfoLevel)
		zapLogger := zap.New(core)
		logger := NewStructuredAuditLogger(zapLogger, 1.0, true)

		event := &KeyLifecycleEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeKeyUpdated,
				ActorInfo{UserID: "admin1"},
				ResourceInfo{Type: "api_key", ID: "key-hash-123"},
				OutcomeSuccess,
			),
			Operation:    "update",
			TargetUserID: "user1",
		}

		err := logger.LogKeyUpdated(ctx, event)

		require.NoError(t, err)
		assert.Equal(t, 1, logs.Len())

		logEntry := logs.All()[0]
		assert.Equal(t, EventTypeKeyUpdated, logEntry.ContextMap()["event_type"])
	})

	t.Run("handles nil event gracefully", func(t *testing.T) {
		logger := NewStructuredAuditLogger(nil, 1.0, true)

		err := logger.LogKeyUpdated(ctx, nil)

		require.NoError(t, err)
	})
}

func TestStructuredAuditLogger_LogKeyDeleted(t *testing.T) {
	ctx := context.Background()

	t.Run("logs key deletion event", func(t *testing.T) {
		core, logs := observer.New(zapcore.InfoLevel)
		zapLogger := zap.New(core)
		logger := NewStructuredAuditLogger(zapLogger, 1.0, true)

		event := &KeyLifecycleEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeKeyDeleted,
				ActorInfo{UserID: "admin1"},
				ResourceInfo{Type: "api_key", ID: "key-hash-123"},
				OutcomeSuccess,
			),
			Operation:    "delete",
			TargetUserID: "user1",
		}

		err := logger.LogKeyDeleted(ctx, event)

		require.NoError(t, err)
		assert.Equal(t, 1, logs.Len())

		logEntry := logs.All()[0]
		assert.Equal(t, EventTypeKeyDeleted, logEntry.ContextMap()["event_type"])
	})

	t.Run("handles nil event gracefully", func(t *testing.T) {
		logger := NewStructuredAuditLogger(nil, 1.0, true)

		err := logger.LogKeyDeleted(ctx, nil)

		require.NoError(t, err)
	})
}

func TestStructuredAuditLogger_LogKeyAccessed(t *testing.T) {
	ctx := context.Background()

	t.Run("logs key access with 100% sample rate", func(t *testing.T) {
		core, logs := observer.New(zapcore.InfoLevel)
		zapLogger := zap.New(core)
		logger := NewStructuredAuditLogger(zapLogger, 1.0, true)

		event := &KeyAccessEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeKeyAccessed,
				ActorInfo{UserID: "user1"},
				ResourceInfo{Type: "endpoint", ID: "/api/users"},
				OutcomeSuccess,
			),
		}

		err := logger.LogKeyAccessed(ctx, event)

		require.NoError(t, err)
		assert.Equal(t, 1, logs.Len())
	})

	t.Run("respects sample rate for key access", func(t *testing.T) {
		core, logs := observer.New(zapcore.InfoLevel)
		zapLogger := zap.New(core)
		logger := NewStructuredAuditLogger(zapLogger, 0.0, true) // 0% sample rate

		event := &KeyAccessEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeKeyAccessed,
				ActorInfo{UserID: "user1"},
				ResourceInfo{Type: "endpoint", ID: "/api/users"},
				OutcomeSuccess,
			),
		}

		err := logger.LogKeyAccessed(ctx, event)

		require.NoError(t, err)
		assert.Equal(t, 0, logs.Len(), "access should not be logged with 0% sample rate")
	})

	t.Run("handles nil event gracefully", func(t *testing.T) {
		logger := NewStructuredAuditLogger(nil, 1.0, true)

		err := logger.LogKeyAccessed(ctx, nil)

		require.NoError(t, err)
	})
}

func TestStructuredAuditLogger_LogSecurityEvent(t *testing.T) {
	ctx := context.Background()

	t.Run("logs security event always (no sampling)", func(t *testing.T) {
		core, logs := observer.New(zapcore.WarnLevel)
		zapLogger := zap.New(core)
		logger := NewStructuredAuditLogger(zapLogger, 0.0, false) // 0% sample rate

		event := &SecurityEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeSecurityThreat,
				ActorInfo{IPAddress: "192.168.1.100"},
				ResourceInfo{Type: "endpoint", ID: "/api/users"},
				OutcomeBlocked,
			),
			ThreatType:     ThreatTypeBruteForce,
			Severity:       SeverityHigh,
			Details:        "Multiple failed login attempts",
			Indicators:     []string{"failed_count=10", "time_window=60s"},
			Recommendation: "Block IP temporarily",
		}

		err := logger.LogSecurityEvent(ctx, event)

		require.NoError(t, err)
		assert.Equal(t, 1, logs.Len(), "security event should always be logged")

		// Verify log structure
		logEntry := logs.All()[0]
		assert.Equal(t, zapcore.WarnLevel, logEntry.Level, "security events use Warn level")
		assert.Equal(t, "SECURITY_EVENT", logEntry.Message)

		// Verify fields
		contextMap := logEntry.ContextMap()
		assert.Equal(t, EventTypeSecurityThreat, contextMap["event_type"])
		assert.Equal(t, ThreatTypeBruteForce, contextMap["threat_type"])
		assert.Equal(t, SeverityHigh, contextMap["severity"])
		assert.Equal(t, "Multiple failed login attempts", contextMap["details"])
		assert.Equal(t, "Block IP temporarily", contextMap["recommendation"])
		assert.Equal(t, "192.168.1.100", contextMap["ip_address"])
	})

	t.Run("handles nil event gracefully", func(t *testing.T) {
		core, logs := observer.New(zapcore.WarnLevel)
		zapLogger := zap.New(core)
		logger := NewStructuredAuditLogger(zapLogger, 1.0, true)

		err := logger.LogSecurityEvent(ctx, nil)

		require.NoError(t, err)
		assert.Equal(t, 0, logs.Len())
	})
}

func TestStructuredAuditLogger_ConcurrentAccess(t *testing.T) {
	ctx := context.Background()

	t.Run("concurrent logging is thread-safe", func(t *testing.T) {
		core, logs := observer.New(zapcore.InfoLevel)
		zapLogger := zap.New(core)
		logger := NewStructuredAuditLogger(zapLogger, 1.0, true)

		iterations := 100
		done := make(chan bool)

		// Launch concurrent loggers
		for i := 0; i < iterations; i++ {
			go func(id int) {
				event := &AuthAttemptEvent{
					BaseAuditEvent: NewBaseAuditEvent(
						EventTypeAuthSuccess,
						ActorInfo{UserID: "user1"},
						ResourceInfo{},
						OutcomeSuccess,
					),
				}
				logger.LogAuthAttempt(ctx, event)
				done <- true
			}(i)
		}

		// Wait for all goroutines
		for i := 0; i < iterations; i++ {
			<-done
		}

		// Should have logged all events
		assert.Equal(t, iterations, logs.Len(), "all events should be logged")
	})
}

func TestStructuredAuditLogger_Integration(t *testing.T) {
	ctx := context.Background()

	t.Run("full audit trail for key lifecycle", func(t *testing.T) {
		core, logs := observer.New(zapcore.InfoLevel)
		zapLogger := zap.New(core)
		logger := NewStructuredAuditLogger(zapLogger, 1.0, true)

		// 1. Create key
		createEvent := &KeyLifecycleEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeKeyCreated,
				ActorInfo{UserID: "admin1", OrgID: "org1"},
				ResourceInfo{Type: "api_key", ID: "key-123"},
				OutcomeSuccess,
			),
			Operation:    "create",
			TargetUserID: "user1",
		}
		logger.LogKeyCreated(ctx, createEvent)

		// 2. Access with key
		accessEvent := &KeyAccessEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeKeyAccessed,
				ActorInfo{UserID: "user1", OrgID: "org1"},
				ResourceInfo{Type: "endpoint", ID: "/api/data"},
				OutcomeSuccess,
			),
		}
		logger.LogKeyAccessed(ctx, accessEvent)

		// 3. Update key
		updateEvent := &KeyLifecycleEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeKeyUpdated,
				ActorInfo{UserID: "admin1", OrgID: "org1"},
				ResourceInfo{Type: "api_key", ID: "key-123"},
				OutcomeSuccess,
			),
			Operation:    "update",
			TargetUserID: "user1",
			TargetOrgID:  "org1",
		}
		logger.LogKeyUpdated(ctx, updateEvent)

		// 4. Delete key
		deleteEvent := &KeyLifecycleEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeKeyDeleted,
				ActorInfo{UserID: "admin1", OrgID: "org1"},
				ResourceInfo{Type: "api_key", ID: "key-123"},
				OutcomeSuccess,
			),
			Operation: "delete",
		}
		logger.LogKeyDeleted(ctx, deleteEvent)

		// Verify all events were logged
		assert.Equal(t, 4, logs.Len(), "should log all 4 lifecycle events")

		// Verify event types
		eventTypes := make([]string, 0)
		for _, entry := range logs.All() {
			eventTypes = append(eventTypes, entry.ContextMap()["event_type"].(string))
		}

		assert.Contains(t, eventTypes, EventTypeKeyCreated)
		assert.Contains(t, eventTypes, EventTypeKeyAccessed)
		assert.Contains(t, eventTypes, EventTypeKeyUpdated)
		assert.Contains(t, eventTypes, EventTypeKeyDeleted)
	})
}

func BenchmarkStructuredAuditLogger(b *testing.B) {
	ctx := context.Background()
	logger := NewStructuredAuditLogger(zap.NewNop(), 1.0, true)

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
			logger.LogAuthAttempt(ctx, event)
		}
	})

	b.Run("LogAuthAttempt with sampling 50%", func(b *testing.B) {
		samplingLogger := NewStructuredAuditLogger(zap.NewNop(), 0.5, true)
		for i := 0; i < b.N; i++ {
			samplingLogger.LogAuthAttempt(ctx, event)
		}
	})
}
