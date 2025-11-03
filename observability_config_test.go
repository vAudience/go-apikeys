package apikeys

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewObservabilityConfig(t *testing.T) {
	t.Run("creates config with default values", func(t *testing.T) {
		config := NewObservabilityConfig()

		require.NotNil(t, config)
		assert.False(t, config.EnableMetrics)
		assert.False(t, config.EnableAudit)
		assert.False(t, config.EnableTracing)
		assert.Equal(t, "apikeys", config.MetricsNamespace)
		assert.False(t, config.AuditSuccessEvents)
		assert.Equal(t, 1.0, config.AuditSampleRate)
		assert.Equal(t, "", config.ComplianceMode)
		assert.Equal(t, 365, config.RetentionDays)
	})
}

func TestObservabilityConfig_Validate(t *testing.T) {
	t.Run("valid config passes validation", func(t *testing.T) {
		config := &ObservabilityConfig{
			EnableMetrics:      true,
			EnableAudit:        true,
			MetricsNamespace:   "myapp",
			AuditSuccessEvents: true,
			AuditSampleRate:    0.5,
			ComplianceMode:     "soc2",
			RetentionDays:      365,
		}

		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("nil config is valid", func(t *testing.T) {
		var config *ObservabilityConfig
		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("rejects sample rate < 0", func(t *testing.T) {
		config := &ObservabilityConfig{
			AuditSampleRate: -0.1,
		}

		err := config.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "between 0.0 and 1.0")
	})

	t.Run("rejects sample rate > 1", func(t *testing.T) {
		config := &ObservabilityConfig{
			AuditSampleRate: 1.5,
		}

		err := config.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "between 0.0 and 1.0")
	})

	t.Run("accepts sample rate boundaries", func(t *testing.T) {
		config1 := &ObservabilityConfig{AuditSampleRate: 0.0}
		assert.NoError(t, config1.Validate())

		config2 := &ObservabilityConfig{AuditSampleRate: 1.0}
		assert.NoError(t, config2.Validate())
	})

	t.Run("rejects negative retention days", func(t *testing.T) {
		config := &ObservabilityConfig{
			RetentionDays: -1,
		}

		err := config.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "non-negative")
	})

	t.Run("accepts zero retention days", func(t *testing.T) {
		config := &ObservabilityConfig{
			RetentionDays: 0,
		}

		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("accepts valid compliance modes", func(t *testing.T) {
		modes := []string{"", "soc2", "pci-dss", "gdpr", "hipaa"}

		for _, mode := range modes {
			config := &ObservabilityConfig{
				ComplianceMode: mode,
			}
			err := config.Validate()
			assert.NoError(t, err, "mode %s should be valid", mode)
		}
	})

	t.Run("rejects invalid compliance mode", func(t *testing.T) {
		config := &ObservabilityConfig{
			ComplianceMode: "invalid-mode",
		}

		err := config.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be one of")
	})
}

func TestObservabilityConfig_IsComplianceModeEnabled(t *testing.T) {
	t.Run("returns false for nil config", func(t *testing.T) {
		var config *ObservabilityConfig
		assert.False(t, config.IsComplianceModeEnabled())
	})

	t.Run("returns false for empty compliance mode", func(t *testing.T) {
		config := &ObservabilityConfig{
			ComplianceMode: "",
		}
		assert.False(t, config.IsComplianceModeEnabled())
	})

	t.Run("returns true for soc2 mode", func(t *testing.T) {
		config := &ObservabilityConfig{
			ComplianceMode: "soc2",
		}
		assert.True(t, config.IsComplianceModeEnabled())
	})

	t.Run("returns true for pci-dss mode", func(t *testing.T) {
		config := &ObservabilityConfig{
			ComplianceMode: "pci-dss",
		}
		assert.True(t, config.IsComplianceModeEnabled())
	})

	t.Run("returns true for gdpr mode", func(t *testing.T) {
		config := &ObservabilityConfig{
			ComplianceMode: "gdpr",
		}
		assert.True(t, config.IsComplianceModeEnabled())
	})

	t.Run("returns true for hipaa mode", func(t *testing.T) {
		config := &ObservabilityConfig{
			ComplianceMode: "hipaa",
		}
		assert.True(t, config.IsComplianceModeEnabled())
	})
}

func TestObservabilityConfig_ShouldAuditSuccessEvents(t *testing.T) {
	t.Run("returns false for nil config", func(t *testing.T) {
		var config *ObservabilityConfig
		assert.False(t, config.ShouldAuditSuccessEvents())
	})

	t.Run("returns false when audit disabled", func(t *testing.T) {
		config := &ObservabilityConfig{
			EnableAudit:        false,
			AuditSuccessEvents: true,
		}
		assert.False(t, config.ShouldAuditSuccessEvents())
	})

	t.Run("returns false when audit enabled but success events disabled", func(t *testing.T) {
		config := &ObservabilityConfig{
			EnableAudit:        true,
			AuditSuccessEvents: false,
			ComplianceMode:     "", // No compliance mode
		}
		assert.False(t, config.ShouldAuditSuccessEvents())
	})

	t.Run("returns true when audit and success events enabled", func(t *testing.T) {
		config := &ObservabilityConfig{
			EnableAudit:        true,
			AuditSuccessEvents: true,
		}
		assert.True(t, config.ShouldAuditSuccessEvents())
	})

	t.Run("returns true in compliance mode even if success events disabled", func(t *testing.T) {
		config := &ObservabilityConfig{
			EnableAudit:        true,
			AuditSuccessEvents: false,
			ComplianceMode:     "soc2",
		}
		// Compliance mode overrides AuditSuccessEvents setting
		assert.True(t, config.ShouldAuditSuccessEvents())
	})

	t.Run("compliance modes always audit success", func(t *testing.T) {
		modes := []string{"soc2", "pci-dss", "gdpr", "hipaa"}

		for _, mode := range modes {
			config := &ObservabilityConfig{
				EnableAudit:        true,
				AuditSuccessEvents: false, // Explicitly disabled
				ComplianceMode:     mode,
			}
			assert.True(t, config.ShouldAuditSuccessEvents(),
				"compliance mode %s should always audit success", mode)
		}
	})
}

func TestObservabilityConfig_ComplianceModeRequirements(t *testing.T) {
	t.Run("soc2 mode requirements", func(t *testing.T) {
		config := &ObservabilityConfig{
			EnableAudit:        true,
			ComplianceMode:     "soc2",
			AuditSuccessEvents: false, // Will be overridden
			AuditSampleRate:    0.5,   // Should be 1.0 for compliance
			RetentionDays:      90,    // Should be ≥365 for compliance
		}

		// Config is technically valid, but not compliant
		err := config.Validate()
		assert.NoError(t, err)

		// But compliance mode should force success audit
		assert.True(t, config.ShouldAuditSuccessEvents())
		assert.True(t, config.IsComplianceModeEnabled())
	})

	t.Run("compliance mode with audit disabled is valid but ineffective", func(t *testing.T) {
		config := &ObservabilityConfig{
			EnableAudit:    false, // Audit disabled
			ComplianceMode: "soc2",
		}

		// Config is valid (no hard requirement that audit must be enabled)
		err := config.Validate()
		assert.NoError(t, err)

		// But won't audit anything
		assert.False(t, config.ShouldAuditSuccessEvents())
	})
}

func TestObservabilityConfig_EdgeCases(t *testing.T) {
	t.Run("very long compliance mode string", func(t *testing.T) {
		config := &ObservabilityConfig{
			ComplianceMode: "this-is-a-very-long-invalid-compliance-mode-string",
		}

		err := config.Validate()
		require.Error(t, err)
	})

	t.Run("compliance mode is case sensitive", func(t *testing.T) {
		config := &ObservabilityConfig{
			ComplianceMode: "SOC2", // uppercase
		}

		err := config.Validate()
		require.Error(t, err, "compliance mode should be lowercase")
	})

	t.Run("sample rate edge values", func(t *testing.T) {
		// Test very small positive value
		config1 := &ObservabilityConfig{
			AuditSampleRate: 0.0001,
		}
		assert.NoError(t, config1.Validate())

		// Test value very close to 1.0
		config2 := &ObservabilityConfig{
			AuditSampleRate: 0.9999,
		}
		assert.NoError(t, config2.Validate())
	})

	t.Run("large retention days", func(t *testing.T) {
		config := &ObservabilityConfig{
			RetentionDays: 36500, // 100 years
		}

		err := config.Validate()
		assert.NoError(t, err) // Should be valid, even if impractical
	})
}

func TestObservabilityConfig_ProviderConfiguration(t *testing.T) {
	t.Run("custom providers can be set", func(t *testing.T) {
		metrics := newMockMetricsProvider()
		audit := newMockAuditProvider()
		tracing := &NoOpTracingProvider{}

		config := &ObservabilityConfig{
			EnableMetrics:   true,
			EnableAudit:     true,
			EnableTracing:   true,
			MetricsProvider: metrics,
			AuditProvider:   audit,
			TracingProvider: tracing,
		}

		err := config.Validate()
		assert.NoError(t, err)
		assert.Equal(t, metrics, config.MetricsProvider)
		assert.Equal(t, audit, config.AuditProvider)
		assert.Equal(t, tracing, config.TracingProvider)
	})

	t.Run("nil providers are valid", func(t *testing.T) {
		config := &ObservabilityConfig{
			EnableMetrics:   true,
			EnableAudit:     true,
			MetricsProvider: nil, // Will be replaced with default
			AuditProvider:   nil, // Will be replaced with default
		}

		err := config.Validate()
		assert.NoError(t, err)
	})
}
