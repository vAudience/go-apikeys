package apikeys

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBaseAuditEvent(t *testing.T) {
	t.Run("creates event with all fields initialized", func(t *testing.T) {
		actor := ActorInfo{UserID: "user1", OrgID: "org1"}
		resource := ResourceInfo{Type: "api_key", ID: "key-123"}

		before := time.Now().UTC()
		event := NewBaseAuditEvent(EventTypeAuthSuccess, actor, resource, OutcomeSuccess)
		after := time.Now().UTC()

		// Verify EventID is a valid UUID
		_, err := uuid.Parse(event.EventID)
		assert.NoError(t, err, "EventID should be a valid UUID")

		// Verify EventType
		assert.Equal(t, EventTypeAuthSuccess, event.EventType)

		// Verify Timestamp is recent and in UTC
		assert.True(t, !event.Timestamp.Before(before), "timestamp should be after test start")
		assert.True(t, !event.Timestamp.After(after), "timestamp should be before test end")
		assert.Equal(t, time.UTC, event.Timestamp.Location())

		// Verify Actor
		assert.Equal(t, "user1", event.Actor.UserID)
		assert.Equal(t, "org1", event.Actor.OrgID)

		// Verify Resource
		assert.Equal(t, "api_key", event.Resource.Type)
		assert.Equal(t, "key-123", event.Resource.ID)

		// Verify Outcome
		assert.Equal(t, OutcomeSuccess, event.Outcome)

		// Verify Metadata is initialized (not nil)
		assert.NotNil(t, event.Metadata)
		assert.Equal(t, 0, len(event.Metadata))
	})

	t.Run("creates unique event IDs", func(t *testing.T) {
		event1 := NewBaseAuditEvent(EventTypeAuthSuccess, ActorInfo{}, ResourceInfo{}, OutcomeSuccess)
		event2 := NewBaseAuditEvent(EventTypeAuthSuccess, ActorInfo{}, ResourceInfo{}, OutcomeSuccess)

		assert.NotEqual(t, event1.EventID, event2.EventID, "each event should have unique ID")
	})

	t.Run("works with empty actor and resource", func(t *testing.T) {
		event := NewBaseAuditEvent(EventTypeAuthFailure, ActorInfo{}, ResourceInfo{}, OutcomeFailure)

		assert.NotEmpty(t, event.EventID)
		assert.Equal(t, EventTypeAuthFailure, event.EventType)
		assert.Equal(t, OutcomeFailure, event.Outcome)
	})

	t.Run("accepts different event types", func(t *testing.T) {
		eventTypes := []string{
			EventTypeAuthAttempt,
			EventTypeAuthSuccess,
			EventTypeAuthFailure,
			EventTypeKeyCreated,
			EventTypeKeyUpdated,
			EventTypeKeyDeleted,
			EventTypeKeyAccessed,
			EventTypeSecurityThreat,
			EventTypeSecurityBlocked,
		}

		for _, eventType := range eventTypes {
			event := NewBaseAuditEvent(eventType, ActorInfo{}, ResourceInfo{}, OutcomeSuccess)
			assert.Equal(t, eventType, event.EventType, "event type %s should be set correctly", eventType)
		}
	})
}

func TestBaseAuditEvent_JSONSerialization(t *testing.T) {
	t.Run("marshals to JSON correctly", func(t *testing.T) {
		event := NewBaseAuditEvent(
			EventTypeAuthSuccess,
			ActorInfo{
				UserID:     "user1",
				OrgID:      "org1",
				IPAddress:  "192.168.1.1",
				UserAgent:  "Mozilla/5.0",
			},
			ResourceInfo{
				Type: "endpoint",
				ID:   "/api/users",
				Name: "User API",
			},
			OutcomeSuccess,
		)
		event.TraceID = "trace-123"
		event.SpanID = "span-456"
		event.Metadata["custom"] = "value"

		jsonBytes, err := json.Marshal(event)
		require.NoError(t, err)

		// Unmarshal to verify structure
		var unmarshaled BaseAuditEvent
		err = json.Unmarshal(jsonBytes, &unmarshaled)
		require.NoError(t, err)

		assert.Equal(t, event.EventID, unmarshaled.EventID)
		assert.Equal(t, event.EventType, unmarshaled.EventType)
		assert.Equal(t, "user1", unmarshaled.Actor.UserID)
		assert.Equal(t, "org1", unmarshaled.Actor.OrgID)
		assert.Equal(t, "192.168.1.1", unmarshaled.Actor.IPAddress)
		assert.Equal(t, "endpoint", unmarshaled.Resource.Type)
		assert.Equal(t, "/api/users", unmarshaled.Resource.ID)
		assert.Equal(t, "User API", unmarshaled.Resource.Name)
		assert.Equal(t, "trace-123", unmarshaled.TraceID)
		assert.Equal(t, "span-456", unmarshaled.SpanID)
		assert.Equal(t, "value", unmarshaled.Metadata["custom"])
	})

	t.Run("omits empty optional fields", func(t *testing.T) {
		event := NewBaseAuditEvent(
			EventTypeAuthSuccess,
			ActorInfo{},
			ResourceInfo{Type: "test"},
			OutcomeSuccess,
		)

		jsonBytes, err := json.Marshal(event)
		require.NoError(t, err)

		var jsonMap map[string]interface{}
		err = json.Unmarshal(jsonBytes, &jsonMap)
		require.NoError(t, err)

		// TraceID and SpanID should be omitted when empty
		_, hasTraceID := jsonMap["trace_id"]
		_, hasSpanID := jsonMap["span_id"]
		assert.False(t, hasTraceID, "empty trace_id should be omitted")
		assert.False(t, hasSpanID, "empty span_id should be omitted")
	})
}

func TestAuthAttemptEvent_Structure(t *testing.T) {
	t.Run("embeds BaseAuditEvent", func(t *testing.T) {
		event := &AuthAttemptEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeAuthSuccess,
				ActorInfo{UserID: "user1"},
				ResourceInfo{Type: "endpoint"},
				OutcomeSuccess,
			),
			Method:      "api_key",
			KeyProvided: true,
			KeyValid:    true,
			KeyFound:    true,
			LatencyMS:   15,
			Endpoint:    "/api/test",
			HTTPMethod:  "GET",
			CacheHit:    true,
		}

		// Verify BaseAuditEvent fields are accessible
		assert.NotEmpty(t, event.EventID)
		assert.Equal(t, EventTypeAuthSuccess, event.EventType)
		assert.Equal(t, "user1", event.Actor.UserID)

		// Verify AuthAttemptEvent-specific fields
		assert.Equal(t, "api_key", event.Method)
		assert.True(t, event.KeyProvided)
		assert.True(t, event.KeyValid)
		assert.True(t, event.KeyFound)
		assert.Equal(t, int64(15), event.LatencyMS)
		assert.Equal(t, "/api/test", event.Endpoint)
		assert.Equal(t, "GET", event.HTTPMethod)
		assert.True(t, event.CacheHit)
	})

	t.Run("marshals to JSON with all fields", func(t *testing.T) {
		event := &AuthAttemptEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeAuthFailure,
				ActorInfo{UserID: "user1"},
				ResourceInfo{Type: "endpoint"},
				OutcomeFailure,
			),
			Method:      "api_key",
			KeyProvided: true,
			KeyValid:    false,
			KeyFound:    false,
			LatencyMS:   5,
			Endpoint:    "/api/test",
			HTTPMethod:  "POST",
			ErrorCode:   "INVALID_KEY",
			CacheHit:    false,
		}

		jsonBytes, err := json.Marshal(event)
		require.NoError(t, err)

		var unmarshaled AuthAttemptEvent
		err = json.Unmarshal(jsonBytes, &unmarshaled)
		require.NoError(t, err)

		assert.Equal(t, event.EventID, unmarshaled.EventID)
		assert.Equal(t, "api_key", unmarshaled.Method)
		assert.False(t, unmarshaled.KeyValid)
		assert.Equal(t, "INVALID_KEY", unmarshaled.ErrorCode)
	})
}

func TestKeyLifecycleEvent_Structure(t *testing.T) {
	t.Run("embeds BaseAuditEvent", func(t *testing.T) {
		event := &KeyLifecycleEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeKeyCreated,
				ActorInfo{UserID: "admin1"},
				ResourceInfo{Type: "api_key"},
				OutcomeSuccess,
			),
			Operation:      "create",
			TargetUserID:   "user1",
			TargetOrgID:    "org1",
			Reason:         "New service account",
			ApprovalTicket: "TICKET-123",
		}

		assert.NotEmpty(t, event.EventID)
		assert.Equal(t, EventTypeKeyCreated, event.EventType)
		assert.Equal(t, "create", event.Operation)
		assert.Equal(t, "user1", event.TargetUserID)
		assert.Equal(t, "org1", event.TargetOrgID)
		assert.Equal(t, "New service account", event.Reason)
		assert.Equal(t, "TICKET-123", event.ApprovalTicket)
	})

	t.Run("supports before and after state", func(t *testing.T) {
		beforeState := &APIKeyInfoSanitized{
			APIKeyHash: "old-hash",
			UserID:     "user1",
			Name:       "Old Name",
		}

		afterState := &APIKeyInfoSanitized{
			APIKeyHash: "old-hash",
			UserID:     "user1",
			Name:       "New Name",
		}

		event := &KeyLifecycleEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeKeyUpdated,
				ActorInfo{UserID: "admin1"},
				ResourceInfo{Type: "api_key"},
				OutcomeSuccess,
			),
			Operation:   "update",
			BeforeState: beforeState,
			AfterState:  afterState,
		}

		require.NotNil(t, event.BeforeState)
		require.NotNil(t, event.AfterState)
		assert.Equal(t, "Old Name", event.BeforeState.Name)
		assert.Equal(t, "New Name", event.AfterState.Name)
	})
}

func TestKeyAccessEvent_Structure(t *testing.T) {
	t.Run("embeds BaseAuditEvent", func(t *testing.T) {
		event := &KeyAccessEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeKeyAccessed,
				ActorInfo{UserID: "user1"},
				ResourceInfo{Type: "endpoint"},
				OutcomeSuccess,
			),
			Endpoint:       "/api/users",
			HTTPMethod:     "GET",
			ResponseStatus: 200,
			LatencyMS:      25,
			DataAccessed:   []string{"user_email", "user_phone"},
		}

		assert.Equal(t, "/api/users", event.Endpoint)
		assert.Equal(t, "GET", event.HTTPMethod)
		assert.Equal(t, 200, event.ResponseStatus)
		assert.Equal(t, int64(25), event.LatencyMS)
		assert.Len(t, event.DataAccessed, 2)
		assert.Contains(t, event.DataAccessed, "user_email")
	})

	t.Run("marshals to JSON correctly", func(t *testing.T) {
		event := &KeyAccessEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeKeyAccessed,
				ActorInfo{UserID: "user1"},
				ResourceInfo{Type: "endpoint"},
				OutcomeSuccess,
			),
			Endpoint:       "/api/data",
			HTTPMethod:     "POST",
			ResponseStatus: 201,
			LatencyMS:      30,
		}

		jsonBytes, err := json.Marshal(event)
		require.NoError(t, err)

		var unmarshaled KeyAccessEvent
		err = json.Unmarshal(jsonBytes, &unmarshaled)
		require.NoError(t, err)

		assert.Equal(t, "/api/data", unmarshaled.Endpoint)
		assert.Equal(t, 201, unmarshaled.ResponseStatus)
	})
}

func TestSecurityEvent_Structure(t *testing.T) {
	t.Run("embeds BaseAuditEvent", func(t *testing.T) {
		event := &SecurityEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeSecurityThreat,
				ActorInfo{IPAddress: "192.168.1.100"},
				ResourceInfo{Type: "endpoint"},
				OutcomeBlocked,
			),
			ThreatType:     ThreatTypeBruteForce,
			Severity:       SeverityHigh,
			Details:        "Multiple failed attempts",
			Indicators:     []string{"failed_count=10", "time_window=60s"},
			Recommendation: "Block IP",
		}

		assert.Equal(t, ThreatTypeBruteForce, event.ThreatType)
		assert.Equal(t, SeverityHigh, event.Severity)
		assert.Equal(t, "Multiple failed attempts", event.Details)
		assert.Len(t, event.Indicators, 2)
		assert.Equal(t, "Block IP", event.Recommendation)
	})

	t.Run("supports all threat types", func(t *testing.T) {
		threatTypes := []string{
			ThreatTypeBruteForce,
			ThreatTypeEnumeration,
			ThreatTypeSuspiciousPattern,
			ThreatTypeRateLimitExceeded,
		}

		for _, threatType := range threatTypes {
			event := &SecurityEvent{
				BaseAuditEvent: NewBaseAuditEvent(
					EventTypeSecurityThreat,
					ActorInfo{},
					ResourceInfo{},
					OutcomeBlocked,
				),
				ThreatType: threatType,
			}
			assert.Equal(t, threatType, event.ThreatType)
		}
	})

	t.Run("supports all severity levels", func(t *testing.T) {
		severities := []string{
			SeverityLow,
			SeverityMedium,
			SeverityHigh,
			SeverityCritical,
		}

		for _, severity := range severities {
			event := &SecurityEvent{
				BaseAuditEvent: NewBaseAuditEvent(
					EventTypeSecurityThreat,
					ActorInfo{},
					ResourceInfo{},
					OutcomeBlocked,
				),
				Severity: severity,
			}
			assert.Equal(t, severity, event.Severity)
		}
	})
}

func TestToAuditSanitized(t *testing.T) {
	t.Run("converts APIKeyInfo to sanitized version", func(t *testing.T) {
		info := &APIKeyInfo{
			APIKey:     "secret-key-value", // Should not appear in sanitized version
			APIKeyHash: "hash-123",
			APIKeyHint: "hint-abc",
			UserID:     "user1",
			OrgID:      "org1",
			Name:       "Test Key",
			Email:      "test@example.com",
			Roles:      []string{"admin", "user"},
			Rights:     []string{"read", "write"},
			Metadata:   map[string]any{"custom": "value"},
		}

		sanitized := ToAuditSanitized(info)

		require.NotNil(t, sanitized)
		assert.Equal(t, "hash-123", sanitized.APIKeyHash)
		assert.Equal(t, "hint-abc", sanitized.Hint)
		assert.Equal(t, "user1", sanitized.UserID)
		assert.Equal(t, "org1", sanitized.OrgID)
		assert.Equal(t, "Test Key", sanitized.Name)
		assert.Equal(t, "test@example.com", sanitized.Email)
		assert.Equal(t, []string{"admin", "user"}, sanitized.Roles)
		assert.Equal(t, []string{"read", "write"}, sanitized.Rights)
		assert.Equal(t, "value", sanitized.Metadata["custom"])

		// Verify the actual API key is NOT present
		jsonBytes, err := json.Marshal(sanitized)
		require.NoError(t, err)
		jsonString := string(jsonBytes)
		assert.NotContains(t, jsonString, "secret-key-value", "actual API key should not be in sanitized version")
	})

	t.Run("handles nil input gracefully", func(t *testing.T) {
		sanitized := ToAuditSanitized(nil)
		assert.Nil(t, sanitized)
	})

	t.Run("handles empty APIKeyInfo", func(t *testing.T) {
		info := &APIKeyInfo{}
		sanitized := ToAuditSanitized(info)

		require.NotNil(t, sanitized)
		assert.Empty(t, sanitized.APIKeyHash)
		assert.Empty(t, sanitized.UserID)
		assert.Empty(t, sanitized.OrgID)
	})

	t.Run("handles nil slices and maps", func(t *testing.T) {
		info := &APIKeyInfo{
			APIKeyHash: "hash-123",
			Roles:      nil,
			Rights:     nil,
			Metadata:   nil,
		}

		sanitized := ToAuditSanitized(info)

		require.NotNil(t, sanitized)
		assert.Nil(t, sanitized.Roles)
		assert.Nil(t, sanitized.Rights)
		assert.Nil(t, sanitized.Metadata)
	})
}

func TestActorInfo_JSONSerialization(t *testing.T) {
	t.Run("marshals complete actor info", func(t *testing.T) {
		actor := ActorInfo{
			UserID:      "user1",
			OrgID:       "org1",
			APIKeyHash:  "hash-123",
			IPAddress:   "192.168.1.1",
			UserAgent:   "Mozilla/5.0",
			GeoLocation: "US-CA",
		}

		jsonBytes, err := json.Marshal(actor)
		require.NoError(t, err)

		var unmarshaled ActorInfo
		err = json.Unmarshal(jsonBytes, &unmarshaled)
		require.NoError(t, err)

		assert.Equal(t, actor.UserID, unmarshaled.UserID)
		assert.Equal(t, actor.OrgID, unmarshaled.OrgID)
		assert.Equal(t, actor.APIKeyHash, unmarshaled.APIKeyHash)
		assert.Equal(t, actor.IPAddress, unmarshaled.IPAddress)
		assert.Equal(t, actor.UserAgent, unmarshaled.UserAgent)
		assert.Equal(t, actor.GeoLocation, unmarshaled.GeoLocation)
	})

	t.Run("omits empty fields", func(t *testing.T) {
		actor := ActorInfo{
			UserID: "user1",
		}

		jsonBytes, err := json.Marshal(actor)
		require.NoError(t, err)

		var jsonMap map[string]interface{}
		err = json.Unmarshal(jsonBytes, &jsonMap)
		require.NoError(t, err)

		_, hasOrgID := jsonMap["org_id"]
		_, hasAPIKeyHash := jsonMap["api_key_hash"]
		assert.False(t, hasOrgID, "empty org_id should be omitted")
		assert.False(t, hasAPIKeyHash, "empty api_key_hash should be omitted")
	})
}

func TestResourceInfo_JSONSerialization(t *testing.T) {
	t.Run("marshals complete resource info", func(t *testing.T) {
		resource := ResourceInfo{
			Type: "api_key",
			ID:   "key-123",
			Name: "Production Key",
		}

		jsonBytes, err := json.Marshal(resource)
		require.NoError(t, err)

		var unmarshaled ResourceInfo
		err = json.Unmarshal(jsonBytes, &unmarshaled)
		require.NoError(t, err)

		assert.Equal(t, resource.Type, unmarshaled.Type)
		assert.Equal(t, resource.ID, unmarshaled.ID)
		assert.Equal(t, resource.Name, unmarshaled.Name)
	})

	t.Run("omits empty optional fields", func(t *testing.T) {
		resource := ResourceInfo{
			Type: "endpoint",
		}

		jsonBytes, err := json.Marshal(resource)
		require.NoError(t, err)

		var jsonMap map[string]interface{}
		err = json.Unmarshal(jsonBytes, &jsonMap)
		require.NoError(t, err)

		_, hasID := jsonMap["id"]
		_, hasName := jsonMap["name"]
		assert.False(t, hasID, "empty id should be omitted")
		assert.False(t, hasName, "empty name should be omitted")
	})
}

func TestEventConstants(t *testing.T) {
	t.Run("event type constants are defined", func(t *testing.T) {
		assert.Equal(t, "auth.attempt", EventTypeAuthAttempt)
		assert.Equal(t, "auth.success", EventTypeAuthSuccess)
		assert.Equal(t, "auth.failure", EventTypeAuthFailure)
		assert.Equal(t, "key.created", EventTypeKeyCreated)
		assert.Equal(t, "key.updated", EventTypeKeyUpdated)
		assert.Equal(t, "key.deleted", EventTypeKeyDeleted)
		assert.Equal(t, "key.accessed", EventTypeKeyAccessed)
		assert.Equal(t, "security.threat", EventTypeSecurityThreat)
		assert.Equal(t, "security.blocked", EventTypeSecurityBlocked)
	})

	t.Run("outcome constants are defined", func(t *testing.T) {
		assert.Equal(t, "success", OutcomeSuccess)
		assert.Equal(t, "failure", OutcomeFailure)
		assert.Equal(t, "blocked", OutcomeBlocked)
	})

	t.Run("threat type constants are defined", func(t *testing.T) {
		assert.Equal(t, "brute_force", ThreatTypeBruteForce)
		assert.Equal(t, "enumeration", ThreatTypeEnumeration)
		assert.Equal(t, "suspicious_pattern", ThreatTypeSuspiciousPattern)
		assert.Equal(t, "rate_limit_exceeded", ThreatTypeRateLimitExceeded)
	})

	t.Run("severity constants are defined", func(t *testing.T) {
		assert.Equal(t, "low", SeverityLow)
		assert.Equal(t, "medium", SeverityMedium)
		assert.Equal(t, "high", SeverityHigh)
		assert.Equal(t, "critical", SeverityCritical)
	})
}

func TestAuditEvents_RealWorldScenarios(t *testing.T) {
	t.Run("complete auth failure scenario", func(t *testing.T) {
		event := &AuthAttemptEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeAuthFailure,
				ActorInfo{
					IPAddress:   "203.0.113.42",
					UserAgent:   "curl/7.68.0",
					GeoLocation: "CN",
				},
				ResourceInfo{
					Type: "endpoint",
					ID:   "/api/v1/users",
				},
				OutcomeFailure,
			),
			Method:      "api_key",
			KeyProvided: true,
			KeyValid:    false,
			KeyFound:    false,
			LatencyMS:   12,
			Endpoint:    "/api/v1/users",
			HTTPMethod:  "GET",
			ErrorCode:   "KEY_NOT_FOUND",
			CacheHit:    false,
		}

		// Verify complete structure
		assert.NotEmpty(t, event.EventID)
		assert.Equal(t, EventTypeAuthFailure, event.EventType)
		assert.Equal(t, "203.0.113.42", event.Actor.IPAddress)
		assert.Equal(t, "KEY_NOT_FOUND", event.ErrorCode)

		// Verify it marshals to JSON
		jsonBytes, err := json.Marshal(event)
		require.NoError(t, err)
		assert.Contains(t, string(jsonBytes), "KEY_NOT_FOUND")
	})

	t.Run("complete security threat scenario", func(t *testing.T) {
		event := &SecurityEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeSecurityThreat,
				ActorInfo{
					IPAddress:   "203.0.113.42",
					GeoLocation: "Unknown",
				},
				ResourceInfo{
					Type: "endpoint",
					ID:   "/api/v1/auth",
				},
				OutcomeBlocked,
			),
			ThreatType: ThreatTypeBruteForce,
			Severity:   SeverityCritical,
			Details:    "20 failed authentication attempts in 60 seconds",
			Indicators: []string{
				"failed_attempts=20",
				"time_window=60s",
				"unique_keys_tried=15",
			},
			Recommendation: "Temporarily block IP address for 1 hour",
		}

		assert.Equal(t, ThreatTypeBruteForce, event.ThreatType)
		assert.Equal(t, SeverityCritical, event.Severity)
		assert.Len(t, event.Indicators, 3)

		// Verify it marshals to JSON
		jsonBytes, err := json.Marshal(event)
		require.NoError(t, err)
		assert.Contains(t, string(jsonBytes), "brute_force")
		assert.Contains(t, string(jsonBytes), "critical")
	})
}
