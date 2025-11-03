package apikeys

import (
	"context"
	"encoding/json"
	"math/rand"

	"go.uber.org/zap"
)

// StructuredAuditLogger implements AuditProvider by logging audit events as structured JSON
// using the provided Zap logger. This is the default audit implementation.
type StructuredAuditLogger struct {
	logger      *zap.Logger
	sampleRate  float64
	auditSuccess bool
}

// NewStructuredAuditLogger creates a new StructuredAuditLogger
func NewStructuredAuditLogger(logger *zap.Logger, sampleRate float64, auditSuccess bool) *StructuredAuditLogger {
	if logger == nil {
		logger = zap.NewNop()
	}
	if sampleRate < 0.0 {
		sampleRate = 1.0
	}
	if sampleRate > 1.0 {
		sampleRate = 1.0
	}

	return &StructuredAuditLogger{
		logger:       logger,
		sampleRate:   sampleRate,
		auditSuccess: auditSuccess,
	}
}

// shouldSample returns true if the event should be logged based on sample rate
func (s *StructuredAuditLogger) shouldSample() bool {
	if s.sampleRate >= 1.0 {
		return true
	}
	return rand.Float64() < s.sampleRate
}

// logAuditEvent logs an audit event as structured JSON
func (s *StructuredAuditLogger) logAuditEvent(event interface{}, eventType string) error {
	// Marshal event to JSON
	eventJSON, err := json.Marshal(event)
	if err != nil {
		s.logger.Error("Failed to marshal audit event", zap.Error(err), zap.String("event_type", eventType))
		return err
	}

	// Log as structured data
	s.logger.Info("AUDIT_EVENT",
		zap.String("event_type", eventType),
		zap.ByteString("event", eventJSON),
	)

	return nil
}

// LogAuthAttempt logs an authentication attempt event
func (s *StructuredAuditLogger) LogAuthAttempt(ctx context.Context, event *AuthAttemptEvent) error {
	if event == nil {
		return nil
	}

	// Sample successful auth events based on configuration
	if event.Outcome == OutcomeSuccess {
		if !s.auditSuccess {
			return nil // Skip success events
		}
		if !s.shouldSample() {
			return nil // Skip this event based on sample rate
		}
	}

	// Always log failures and blocked events
	return s.logAuditEvent(event, event.EventType)
}

// LogKeyCreated logs an API key creation event
func (s *StructuredAuditLogger) LogKeyCreated(ctx context.Context, event *KeyLifecycleEvent) error {
	if event == nil {
		return nil
	}
	return s.logAuditEvent(event, EventTypeKeyCreated)
}

// LogKeyUpdated logs an API key update event
func (s *StructuredAuditLogger) LogKeyUpdated(ctx context.Context, event *KeyLifecycleEvent) error {
	if event == nil {
		return nil
	}
	return s.logAuditEvent(event, EventTypeKeyUpdated)
}

// LogKeyDeleted logs an API key deletion event
func (s *StructuredAuditLogger) LogKeyDeleted(ctx context.Context, event *KeyLifecycleEvent) error {
	if event == nil {
		return nil
	}
	return s.logAuditEvent(event, EventTypeKeyDeleted)
}

// LogKeyAccessed logs an API key access/usage event
func (s *StructuredAuditLogger) LogKeyAccessed(ctx context.Context, event *KeyAccessEvent) error {
	if event == nil {
		return nil
	}

	// Sample access events (can be high volume)
	if !s.shouldSample() {
		return nil
	}

	return s.logAuditEvent(event, EventTypeKeyAccessed)
}

// LogSecurityEvent logs a security-related event
func (s *StructuredAuditLogger) LogSecurityEvent(ctx context.Context, event *SecurityEvent) error {
	if event == nil {
		return nil
	}

	// Always log security events (never sample)
	s.logger.Warn("SECURITY_EVENT",
		zap.String("event_type", event.EventType),
		zap.String("threat_type", event.ThreatType),
		zap.String("severity", event.Severity),
		zap.String("details", event.Details),
		zap.Strings("indicators", event.Indicators),
		zap.String("recommendation", event.Recommendation),
		zap.String("event_id", event.EventID),
		zap.Time("timestamp", event.Timestamp),
		zap.String("ip_address", event.Actor.IPAddress),
	)

	return nil
}
