package apikeys

// ObservabilityConfig configures observability features including metrics, audit logging, and tracing.
// All features are opt-in and can be enabled independently.
type ObservabilityConfig struct {
	// EnableMetrics enables operational metrics collection
	EnableMetrics bool

	// EnableAudit enables audit event logging
	EnableAudit bool

	// EnableTracing enables distributed tracing
	EnableTracing bool

	// MetricsProvider is the implementation for metrics collection.
	// If nil when EnableMetrics is true, a no-op provider will be used.
	MetricsProvider MetricsProvider

	// AuditProvider is the implementation for audit logging.
	// If nil when EnableAudit is true, a no-op provider will be used.
	AuditProvider AuditProvider

	// TracingProvider is the implementation for distributed tracing.
	// If nil when EnableTracing is true, a no-op provider will be used.
	TracingProvider TracingProvider

	// MetricsNamespace is the namespace prefix for metrics.
	// Default: "apikeys"
	MetricsNamespace string

	// AuditSuccessEvents determines whether successful authentication events should be audited.
	// This can generate high volume in production. Consider using AuditSampleRate to reduce volume.
	// Default: false
	AuditSuccessEvents bool

	// AuditSampleRate controls the sampling rate for successful authentication events (0.0-1.0).
	// Only applies when AuditSuccessEvents is true.
	// 1.0 = audit all success events, 0.1 = audit 10% of success events
	// Default: 1.0 (audit all)
	AuditSampleRate float64

	// ComplianceMode enables compliance-specific audit features.
	// Supported values: "", "soc2", "pci-dss", "gdpr", "hipaa"
	// Empty string = standard audit logging
	// Default: ""
	ComplianceMode string

	// RetentionDays specifies how long audit logs should be retained (in days).
	// This is advisory - actual retention depends on the AuditProvider implementation.
	// Default: 365 (1 year)
	RetentionDays int
}

// NewObservabilityConfig creates a new ObservabilityConfig with default values
func NewObservabilityConfig() *ObservabilityConfig {
	return &ObservabilityConfig{
		EnableMetrics:      false,
		EnableAudit:        false,
		EnableTracing:      false,
		MetricsNamespace:   "apikeys",
		AuditSuccessEvents: false,
		AuditSampleRate:    1.0,
		ComplianceMode:     "",
		RetentionDays:      365,
	}
}

// Validate validates the observability configuration
func (c *ObservabilityConfig) Validate() error {
	if c == nil {
		return nil // nil config is valid (all features disabled)
	}

	if c.AuditSampleRate < 0.0 || c.AuditSampleRate > 1.0 {
		return NewValidationError("audit_sample_rate", "must be between 0.0 and 1.0")
	}

	if c.RetentionDays < 0 {
		return NewValidationError("retention_days", "must be non-negative")
	}

	// Validate compliance mode
	validModes := map[string]bool{
		"":        true,
		"soc2":    true,
		"pci-dss": true,
		"gdpr":    true,
		"hipaa":   true,
	}
	if !validModes[c.ComplianceMode] {
		return NewValidationError("compliance_mode", "must be one of: '', 'soc2', 'pci-dss', 'gdpr', 'hipaa'")
	}

	return nil
}

// IsComplianceModeEnabled returns true if compliance mode is enabled
func (c *ObservabilityConfig) IsComplianceModeEnabled() bool {
	return c != nil && c.ComplianceMode != ""
}

// ShouldAuditSuccessEvents returns true if successful authentication events should be audited
func (c *ObservabilityConfig) ShouldAuditSuccessEvents() bool {
	if c == nil || !c.EnableAudit {
		return false
	}
	// In compliance mode, always audit success events
	if c.IsComplianceModeEnabled() {
		return true
	}
	return c.AuditSuccessEvents
}
