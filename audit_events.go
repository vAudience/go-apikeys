package apikeys

import (
	"time"

	"github.com/google/uuid"
)

// BaseAuditEvent contains fields common to all audit events
type BaseAuditEvent struct {
	// EventID is a unique identifier for this event (UUID v4)
	EventID string `json:"event_id"`

	// EventType categorizes the event (e.g., "auth.attempt", "key.created")
	EventType string `json:"event_type"`

	// Timestamp is when the event occurred
	Timestamp time.Time `json:"timestamp"`

	// Actor identifies who performed the action
	Actor ActorInfo `json:"actor"`

	// Resource identifies what was affected
	Resource ResourceInfo `json:"resource"`

	// Outcome indicates the result ("success", "failure", "blocked")
	Outcome string `json:"outcome"`

	// Metadata contains additional context-specific information
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// TraceID links this event to distributed traces (OpenTelemetry format)
	TraceID string `json:"trace_id,omitempty"`

	// SpanID identifies the specific span within the trace
	SpanID string `json:"span_id,omitempty"`
}

// ActorInfo identifies who performed an action
type ActorInfo struct {
	// UserID is the ID of the user who performed the action
	UserID string `json:"user_id,omitempty"`

	// OrgID is the organization ID of the actor
	OrgID string `json:"org_id,omitempty"`

	// APIKeyHash is the hash of the API key used (for authenticated actions)
	APIKeyHash string `json:"api_key_hash,omitempty"`

	// IPAddress is the IP address of the actor
	IPAddress string `json:"ip_address,omitempty"`

	// UserAgent is the HTTP user agent string
	UserAgent string `json:"user_agent,omitempty"`

	// GeoLocation is the geographic location (e.g., "US-CA" for California, USA)
	GeoLocation string `json:"geo_location,omitempty"`
}

// ResourceInfo identifies what was affected by an action
type ResourceInfo struct {
	// Type is the resource type ("api_key", "endpoint", etc.)
	Type string `json:"type"`

	// ID is the unique identifier for the resource
	ID string `json:"id,omitempty"`

	// Name is a human-readable name for the resource
	Name string `json:"name,omitempty"`
}

// AuthAttemptEvent represents an authentication attempt
type AuthAttemptEvent struct {
	BaseAuditEvent

	// Method is the authentication method used ("api_key")
	Method string `json:"method"`

	// KeyProvided indicates whether an API key was provided
	KeyProvided bool `json:"key_provided"`

	// KeyValid indicates whether the provided key was valid
	KeyValid bool `json:"key_valid"`

	// KeyFound indicates whether the key exists in the system
	KeyFound bool `json:"key_found"`

	// LatencyMS is the authentication latency in milliseconds
	LatencyMS int64 `json:"latency_ms"`

	// Endpoint is the HTTP endpoint being accessed
	Endpoint string `json:"endpoint"`

	// HTTPMethod is the HTTP method (GET, POST, etc.)
	HTTPMethod string `json:"http_method"`

	// ErrorCode is the error code if authentication failed
	ErrorCode string `json:"error_code,omitempty"`

	// CacheHit indicates whether the authentication used cached data
	CacheHit bool `json:"cache_hit"`
}

// KeyLifecycleEvent represents API key creation, modification, or deletion
type KeyLifecycleEvent struct {
	BaseAuditEvent

	// Operation is the lifecycle operation ("create", "update", "delete")
	Operation string `json:"operation"`

	// TargetUserID is the user ID associated with the API key
	TargetUserID string `json:"target_user_id"`

	// TargetOrgID is the organization ID associated with the API key
	TargetOrgID string `json:"target_org_id"`

	// BeforeState is the state before the operation (for updates and deletes)
	BeforeState *APIKeyInfoSanitized `json:"before_state,omitempty"`

	// AfterState is the state after the operation (for creates and updates)
	AfterState *APIKeyInfoSanitized `json:"after_state,omitempty"`

	// Reason is a human-readable explanation for the operation
	Reason string `json:"reason,omitempty"`

	// ApprovalTicket is a reference to an approval/ticket system
	ApprovalTicket string `json:"approval_ticket,omitempty"`
}

// APIKeyInfoSanitized is a sanitized version of APIKeyInfo for audit logs.
// It excludes sensitive data like the actual API key.
type APIKeyInfoSanitized struct {
	APIKeyHash string         `json:"api_key_hash"`
	UserID     string         `json:"user_id"`
	OrgID      string         `json:"org_id"`
	Name       string         `json:"name,omitempty"`
	Email      string         `json:"email,omitempty"`
	Hint       string         `json:"hint,omitempty"`
	Roles      []string       `json:"roles,omitempty"`
	Rights     []string       `json:"rights,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

// KeyAccessEvent represents an API key being used to access a resource
type KeyAccessEvent struct {
	BaseAuditEvent

	// Endpoint is the HTTP endpoint being accessed
	Endpoint string `json:"endpoint"`

	// HTTPMethod is the HTTP method (GET, POST, etc.)
	HTTPMethod string `json:"http_method"`

	// ResponseStatus is the HTTP response status code
	ResponseStatus int `json:"response_status"`

	// LatencyMS is the request latency in milliseconds
	LatencyMS int64 `json:"latency_ms"`

	// DataAccessed lists sensitive data that was accessed (for compliance)
	DataAccessed []string `json:"data_accessed,omitempty"`
}

// SecurityEvent represents a security-related event (threats, attacks, suspicious activity)
type SecurityEvent struct {
	BaseAuditEvent

	// ThreatType categorizes the threat ("brute_force", "enumeration", "suspicious_pattern")
	ThreatType string `json:"threat_type"`

	// Severity indicates the threat severity ("low", "medium", "high", "critical")
	Severity string `json:"severity"`

	// Details provides a human-readable description of the threat
	Details string `json:"details"`

	// Indicators contains evidence supporting the threat detection
	Indicators []string `json:"indicators,omitempty"`

	// Recommendation suggests actions to take ("block_ip", "alert_admin", "rate_limit")
	Recommendation string `json:"recommendation,omitempty"`
}

// NewBaseAuditEvent creates a new BaseAuditEvent with common fields initialized
func NewBaseAuditEvent(eventType string, actor ActorInfo, resource ResourceInfo, outcome string) BaseAuditEvent {
	return BaseAuditEvent{
		EventID:   uuid.New().String(),
		EventType: eventType,
		Timestamp: time.Now().UTC(),
		Actor:     actor,
		Resource:  resource,
		Outcome:   outcome,
		Metadata:  make(map[string]interface{}),
	}
}

// ToAuditSanitized converts an APIKeyInfo to APIKeyInfoSanitized for audit logging.
// This creates a safe representation for audit logs without the actual API key.
func ToAuditSanitized(info *APIKeyInfo) *APIKeyInfoSanitized {
	if info == nil {
		return nil
	}

	return &APIKeyInfoSanitized{
		APIKeyHash: info.APIKeyHash,
		UserID:     info.UserID,
		OrgID:      info.OrgID,
		Name:       info.Name,
		Email:      info.Email,
		Hint:       info.APIKeyHint,
		Roles:      info.Roles,
		Rights:     info.Rights,
		Metadata:   info.Metadata,
	}
}

// Event type constants
const (
	EventTypeAuthAttempt      = "auth.attempt"
	EventTypeAuthSuccess      = "auth.success"
	EventTypeAuthFailure      = "auth.failure"
	EventTypeKeyCreated       = "key.created"
	EventTypeKeyUpdated       = "key.updated"
	EventTypeKeyDeleted       = "key.deleted"
	EventTypeKeyAccessed      = "key.accessed"
	EventTypeSecurityThreat   = "security.threat"
	EventTypeSecurityBlocked  = "security.blocked"
)

// Outcome constants
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeBlocked = "blocked"
)

// Threat type constants
const (
	ThreatTypeBruteForce       = "brute_force"
	ThreatTypeEnumeration      = "enumeration"
	ThreatTypeSuspiciousPattern = "suspicious_pattern"
	ThreatTypeRateLimitExceeded = "rate_limit_exceeded"
)

// Severity constants
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)
