// Package apikeys provides API key authentication and management middleware for Go applications.
//
// This file tests the bootstrap service functionality including initialization,
// production environment detection, bootstrap key creation, and recovery file handling.
package apikeys

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// =============================================================================
// Production Environment Detection Tests (7 tests)
// =============================================================================

func TestBootstrap_ProductionEnvDetection_ENV(t *testing.T) {
	t.Run("blocks bootstrap when ENV=production without explicit allow", func(t *testing.T) {
		// Setup
		config := &BootstrapConfig{
			IUnderstandSecurityRisks:   true,
			AllowBootstrapInProduction: false,
			AdminUserID:                "test-admin",
			AdminOrgID:                 "test-org",
		}
		_, bootstrap, _ := setupBootstrapTest(t, config)

		// Set production environment
		os.Setenv("ENV", "production")
		defer os.Unsetenv("ENV")

		// Execute
		_, err := bootstrap.Bootstrap(context.Background())

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "production")
		assert.Contains(t, err.Error(), "AllowBootstrapInProduction")
		// Should map to 400 (validation error)
		assert.Equal(t, 400, ErrorToHTTPStatus(err))
	})
}

func TestBootstrap_ProductionEnvDetection_ENVIRONMENT(t *testing.T) {
	t.Run("blocks bootstrap when ENVIRONMENT=production", func(t *testing.T) {
		// Setup
		config := &BootstrapConfig{
			IUnderstandSecurityRisks:   true,
			AllowBootstrapInProduction: false,
			AdminUserID:                "test-admin",
			AdminOrgID:                 "test-org",
		}
		_, bootstrap, _ := setupBootstrapTest(t, config)

		// Set production environment
		os.Setenv("ENVIRONMENT", "production")
		defer os.Unsetenv("ENVIRONMENT")

		// Execute
		_, err := bootstrap.Bootstrap(context.Background())

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "production")
		assert.Equal(t, 400, ErrorToHTTPStatus(err))
	})
}

func TestBootstrap_ProductionEnvDetection_GO_ENV(t *testing.T) {
	t.Run("blocks bootstrap when GO_ENV=production", func(t *testing.T) {
		// Setup
		config := &BootstrapConfig{
			IUnderstandSecurityRisks:   true,
			AllowBootstrapInProduction: false,
			AdminUserID:                "test-admin",
			AdminOrgID:                 "test-org",
		}
		_, bootstrap, _ := setupBootstrapTest(t, config)

		// Set production environment
		os.Setenv("GO_ENV", "production")
		defer os.Unsetenv("GO_ENV")

		// Execute
		_, err := bootstrap.Bootstrap(context.Background())

		// Verify
		require.Error(t, err)
		assert.Contains(t, err.Error(), "production")
		assert.Equal(t, 400, ErrorToHTTPStatus(err))
	})
}

func TestBootstrap_ProductionEnvDetection_CaseInsensitive(t *testing.T) {
	t.Run("blocks bootstrap for case-insensitive 'prod'", func(t *testing.T) {
		testCases := []string{"prod", "PROD", "Prod", "PRODUCTION", "Production"}
		for _, envValue := range testCases {
			t.Run("GO_ENV="+envValue, func(t *testing.T) {
				config := &BootstrapConfig{
					IUnderstandSecurityRisks:   true,
					AllowBootstrapInProduction: false,
					AdminUserID:                "test-admin",
					AdminOrgID:                 "test-org",
				}
				_, bootstrap, _ := setupBootstrapTest(t, config)

				os.Setenv("GO_ENV", envValue)
				defer os.Unsetenv("GO_ENV")

				_, err := bootstrap.Bootstrap(context.Background())
				require.Error(t, err)
				assert.Equal(t, 400, ErrorToHTTPStatus(err))
			})
		}
	})
}

func TestBootstrap_ProductionEnvDetection_AllowedInProduction(t *testing.T) {
	t.Run("allows bootstrap when AllowBootstrapInProduction=true", func(t *testing.T) {
		// Setup
		config := &BootstrapConfig{
			IUnderstandSecurityRisks:   true,
			AllowBootstrapInProduction: true, // Explicitly allow
			AdminUserID:                "test-admin",
			AdminOrgID:                 "test-org",
			AdminEmail:                 "admin@test.com",
		}
		_, bootstrap, _ := setupBootstrapTest(t, config)

		// Set production environment
		os.Setenv("ENV", "production")
		defer os.Unsetenv("ENV")

		// Execute
		apiKey, err := bootstrap.Bootstrap(context.Background())

		// Verify
		require.NoError(t, err)
		require.NotNil(t, apiKey)
		assert.NotEmpty(t, apiKey.APIKey)
		assert.Equal(t, "test-admin", apiKey.UserID)
		assert.Equal(t, "test-org", apiKey.OrgID)
	})
}

func TestBootstrap_ProductionEnvDetection_NonProduction(t *testing.T) {
	t.Run("allows bootstrap in non-production environments", func(t *testing.T) {
		testCases := []string{"development", "dev", "staging", "test", ""}
		for _, envValue := range testCases {
			t.Run("ENV="+envValue, func(t *testing.T) {
				// Clean all environment variables
				os.Unsetenv("ENV")
				os.Unsetenv("ENVIRONMENT")
				os.Unsetenv("GO_ENV")

				if envValue != "" {
					os.Setenv("ENV", envValue)
					defer os.Unsetenv("ENV")
				}

				config := &BootstrapConfig{
					IUnderstandSecurityRisks:   true,
					AllowBootstrapInProduction: false,
					AdminUserID:                "test-admin-" + envValue,
					AdminOrgID:                 "test-org",
					AdminEmail:                 "admin@test.com",
				}
				_, bootstrap, _ := setupBootstrapTest(t, config)

				apiKey, err := bootstrap.Bootstrap(context.Background())
				require.NoError(t, err, "should allow bootstrap in %s environment", envValue)
				require.NotNil(t, apiKey)
				assert.NotEmpty(t, apiKey.APIKey)
			})
		}
	})
}

func TestBootstrap_ProductionEnvDetection_EnvironmentPriority(t *testing.T) {
	t.Run("checks ENV first, then ENVIRONMENT, then GO_ENV", func(t *testing.T) {
		// Setup
		config := &BootstrapConfig{
			IUnderstandSecurityRisks:   true,
			AllowBootstrapInProduction: false,
			AdminUserID:                "test-admin",
			AdminOrgID:                 "test-org",
		}
		_, bootstrap, _ := setupBootstrapTest(t, config)

		// Set ENV to production (highest priority)
		os.Setenv("ENV", "production")
		os.Setenv("ENVIRONMENT", "development")
		os.Setenv("GO_ENV", "test")
		defer func() {
			os.Unsetenv("ENV")
			os.Unsetenv("ENVIRONMENT")
			os.Unsetenv("GO_ENV")
		}()

		_, err := bootstrap.Bootstrap(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "production")
	})
}

// =============================================================================
// Initialization Tests (2 tests)
// =============================================================================

func TestBootstrapService_NewBootstrapService(t *testing.T) {
	t.Run("creates service with provided config", func(t *testing.T) {
		repo := newMockRepository()
		logger := zaptest.NewLogger(t)
		service, err := NewAPIKeyService(repo, logger, "gak_", 32, 0, 0)
		require.NoError(t, err)

		config := &BootstrapConfig{
			IUnderstandSecurityRisks: true,
			AdminUserID:              "custom-admin",
			AdminOrgID:               "custom-org",
			AdminEmail:               "custom@example.com",
			Roles:                    []string{"admin", "superuser"},
		}

		bootstrap := NewBootstrapService(service, config, logger)

		require.NotNil(t, bootstrap)
		assert.Equal(t, "custom-admin", bootstrap.config.AdminUserID)
		assert.Equal(t, "custom-org", bootstrap.config.AdminOrgID)
		assert.Equal(t, "custom@example.com", bootstrap.config.AdminEmail)
		assert.Equal(t, []string{"admin", "superuser"}, bootstrap.config.Roles)
	})

	t.Run("uses default config when nil provided", func(t *testing.T) {
		repo := newMockRepository()
		logger := zaptest.NewLogger(t)
		service, err := NewAPIKeyService(repo, logger, "gak_", 32, 0, 0)
		require.NoError(t, err)

		bootstrap := NewBootstrapService(service, nil, logger)

		require.NotNil(t, bootstrap)
		assert.Equal(t, "bootstrap-admin", bootstrap.config.AdminUserID)
		assert.Equal(t, "system", bootstrap.config.AdminOrgID)
		assert.Equal(t, "admin@system", bootstrap.config.AdminEmail)
		assert.Contains(t, bootstrap.config.Roles, "system_admin")
		assert.True(t, bootstrap.config.Metadata[METADATA_KEY_SYSTEM_ADMIN].(bool))
	})
}

// =============================================================================
// NeedsBootstrap Detection Tests (4 tests)
// =============================================================================

func TestBootstrapService_NeedsBootstrap(t *testing.T) {
	t.Run("returns true when no API keys exist", func(t *testing.T) {
		_, bootstrap, _ := setupBootstrapTest(t, nil)

		needed, err := bootstrap.NeedsBootstrap(context.Background())

		require.NoError(t, err)
		assert.True(t, needed, "should need bootstrap when no keys exist")
	})

	t.Run("returns false when system admin key exists", func(t *testing.T) {
		service, bootstrap, _ := setupBootstrapTest(t, nil)

		// Create a system admin key
		apiKeyInfo := &APIKeyInfo{
			UserID: "admin-user",
			OrgID:  "system",
			Email:  "admin@system.com",
			Metadata: map[string]any{
				METADATA_KEY_SYSTEM_ADMIN: true,
			},
		}
		_, err := service.CreateAPIKey(context.Background(), apiKeyInfo)
		require.NoError(t, err)

		needed, err := bootstrap.NeedsBootstrap(context.Background())

		require.NoError(t, err)
		assert.False(t, needed, "should not need bootstrap when system admin exists")
	})

	t.Run("returns true when keys exist but no system admin", func(t *testing.T) {
		service, bootstrap, _ := setupBootstrapTest(t, nil)

		// Create a regular key without system admin privileges
		apiKeyInfo := &APIKeyInfo{
			UserID: "regular-user",
			OrgID:  "test-org",
			Email:  "user@test.com",
			Roles:  []string{"user"},
		}
		_, err := service.CreateAPIKey(context.Background(), apiKeyInfo)
		require.NoError(t, err)

		needed, err := bootstrap.NeedsBootstrap(context.Background())

		require.NoError(t, err)
		assert.True(t, needed, "should need bootstrap when no system admin exists")
	})

	t.Run("returns true when multiple keys exist but none are system admin", func(t *testing.T) {
		service, bootstrap, _ := setupBootstrapTest(t, nil)

		// Create multiple regular keys
		for i := 0; i < 3; i++ {
			apiKeyInfo := &APIKeyInfo{
				UserID: fmt.Sprintf("user-%d", i),
				OrgID:  "test-org",
				Email:  fmt.Sprintf("user%d@test.com", i),
			}
			_, err := service.CreateAPIKey(context.Background(), apiKeyInfo)
			require.NoError(t, err)
		}

		needed, err := bootstrap.NeedsBootstrap(context.Background())

		require.NoError(t, err)
		assert.True(t, needed, "should need bootstrap when no system admin among multiple keys")
	})
}

// =============================================================================
// Bootstrap Execution Tests (8 tests)
// =============================================================================

func TestBootstrapService_Bootstrap(t *testing.T) {
	t.Run("blocks bootstrap without security risk acknowledgment", func(t *testing.T) {
		config := &BootstrapConfig{
			IUnderstandSecurityRisks: false, // Not acknowledged
			AdminUserID:              "test-admin",
			AdminOrgID:               "test-org",
		}
		_, bootstrap, _ := setupBootstrapTest(t, config)

		_, err := bootstrap.Bootstrap(context.Background())

		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be true")
		assert.Contains(t, err.Error(), "enable bootstrap")
	})

	t.Run("successfully creates bootstrap key", func(t *testing.T) {
		_, bootstrap, _ := setupBootstrapTest(t, nil)

		apiKey, err := bootstrap.Bootstrap(context.Background())

		require.NoError(t, err)
		require.NotNil(t, apiKey)
		assert.NotEmpty(t, apiKey.APIKey)
		assert.NotEmpty(t, apiKey.APIKeyHash)
		assert.NotEmpty(t, apiKey.APIKeyHint)
		assert.Equal(t, "test-admin", apiKey.UserID)
		assert.Equal(t, "test-org", apiKey.OrgID)
		assert.True(t, apiKey.Metadata[METADATA_KEY_SYSTEM_ADMIN].(bool))
		assert.Equal(t, "bootstrap", apiKey.Metadata[METADATA_KEY_CREATED_BY])
	})

	t.Run("fails when bootstrap key already exists", func(t *testing.T) {
		_, bootstrap, _ := setupBootstrapTest(t, nil)

		// Create first bootstrap key
		_, err := bootstrap.Bootstrap(context.Background())
		require.NoError(t, err)

		// Try to create second bootstrap key
		_, err = bootstrap.Bootstrap(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})

	t.Run("sets system admin metadata on bootstrap key", func(t *testing.T) {
		service, bootstrap, _ := setupBootstrapTest(t, nil)

		apiKey, err := bootstrap.Bootstrap(context.Background())
		require.NoError(t, err)

		// Verify IsSystemAdmin returns true
		assert.True(t, service.IsSystemAdmin(apiKey))
	})

	t.Run("respects custom admin user and org IDs", func(t *testing.T) {
		config := &BootstrapConfig{
			IUnderstandSecurityRisks: true,
			AdminUserID:              "custom-admin-123",
			AdminOrgID:               "custom-org-456",
			AdminEmail:               "custom@example.com",
		}
		_, bootstrap, _ := setupBootstrapTest(t, config)

		apiKey, err := bootstrap.Bootstrap(context.Background())

		require.NoError(t, err)
		assert.Equal(t, "custom-admin-123", apiKey.UserID)
		assert.Equal(t, "custom-org-456", apiKey.OrgID)
		assert.Equal(t, "custom@example.com", apiKey.Email)
	})

	t.Run("includes custom roles in bootstrap key", func(t *testing.T) {
		config := &BootstrapConfig{
			IUnderstandSecurityRisks: true,
			AdminUserID:              "admin",
			AdminOrgID:               "org",
			Roles:                    []string{"superadmin", "billing", "support"},
		}
		_, bootstrap, _ := setupBootstrapTest(t, config)

		apiKey, err := bootstrap.Bootstrap(context.Background())

		require.NoError(t, err)
		assert.Equal(t, []string{"superadmin", "billing", "support"}, apiKey.Roles)
	})

	t.Run("includes custom metadata in bootstrap key", func(t *testing.T) {
		config := &BootstrapConfig{
			IUnderstandSecurityRisks: true,
			AdminUserID:              "admin",
			AdminOrgID:               "org",
			Metadata: map[string]any{
				"environment": "staging",
				"version":     "1.0.0",
				"team":        "infrastructure",
			},
		}
		_, bootstrap, _ := setupBootstrapTest(t, config)

		apiKey, err := bootstrap.Bootstrap(context.Background())

		require.NoError(t, err)
		// Custom metadata should be preserved
		assert.Equal(t, "staging", apiKey.Metadata["environment"])
		assert.Equal(t, "1.0.0", apiKey.Metadata["version"])
		assert.Equal(t, "infrastructure", apiKey.Metadata["team"])
		// System metadata should still be set
		assert.True(t, apiKey.Metadata[METADATA_KEY_SYSTEM_ADMIN].(bool))
		assert.Equal(t, "bootstrap", apiKey.Metadata[METADATA_KEY_CREATED_BY])
	})

	t.Run("allows bootstrap when no keys exist but regular keys were added", func(t *testing.T) {
		service, bootstrap, _ := setupBootstrapTest(t, nil)

		// Add a regular key first
		regularKey := &APIKeyInfo{
			UserID: "regular-user",
			OrgID:  "test-org",
			Email:  "user@test.com",
		}
		_, err := service.CreateAPIKey(context.Background(), regularKey)
		require.NoError(t, err)

		// Bootstrap should still work since no system admin exists
		apiKey, err := bootstrap.Bootstrap(context.Background())
		require.NoError(t, err)
		assert.NotEmpty(t, apiKey.APIKey)
		assert.True(t, service.IsSystemAdmin(apiKey))
	})
}

// =============================================================================
// Recovery File Tests (4 tests)
// =============================================================================

func TestBootstrapService_RecoveryFile(t *testing.T) {
	t.Run("creates recovery file when path is provided", func(t *testing.T) {
		// Create temporary directory for recovery file
		tmpDir := t.TempDir()
		recoveryPath := fmt.Sprintf("%s/bootstrap-recovery.txt", tmpDir)

		config := &BootstrapConfig{
			IUnderstandSecurityRisks: true,
			AdminUserID:              "admin",
			AdminOrgID:               "org",
			RecoveryPath:             recoveryPath,
		}
		_, bootstrap, _ := setupBootstrapTest(t, config)

		apiKey, err := bootstrap.Bootstrap(context.Background())

		require.NoError(t, err)
		require.NotEmpty(t, apiKey.APIKey)

		// Verify recovery file was created
		_, err = os.Stat(recoveryPath)
		require.NoError(t, err, "recovery file should exist")

		// Verify file contents
		content, err := os.ReadFile(recoveryPath)
		require.NoError(t, err)
		assert.Contains(t, string(content), apiKey.APIKey)
		assert.Contains(t, string(content), apiKey.UserID)
		assert.Contains(t, string(content), apiKey.OrgID)
		assert.Contains(t, string(content), "BOOTSTRAP API KEY RECOVERY FILE")
	})

	t.Run("does not create recovery file when path is empty", func(t *testing.T) {
		config := &BootstrapConfig{
			IUnderstandSecurityRisks: true,
			AdminUserID:              "admin",
			AdminOrgID:               "org",
			RecoveryPath:             "", // No recovery path
		}
		_, bootstrap, _ := setupBootstrapTest(t, config)

		apiKey, err := bootstrap.Bootstrap(context.Background())

		require.NoError(t, err)
		require.NotEmpty(t, apiKey.APIKey)
		// No file should be created (nothing to check, just verify no error)
	})

	t.Run("recovery file has correct permissions", func(t *testing.T) {
		tmpDir := t.TempDir()
		recoveryPath := fmt.Sprintf("%s/bootstrap-recovery.txt", tmpDir)

		config := &BootstrapConfig{
			IUnderstandSecurityRisks: true,
			AdminUserID:              "admin",
			AdminOrgID:               "org",
			RecoveryPath:             recoveryPath,
		}
		_, bootstrap, _ := setupBootstrapTest(t, config)

		_, err := bootstrap.Bootstrap(context.Background())
		require.NoError(t, err)

		// Check file permissions
		fileInfo, err := os.Stat(recoveryPath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), fileInfo.Mode().Perm(), "file should have 0600 permissions")
	})

	t.Run("bootstrap succeeds even if recovery file write fails", func(t *testing.T) {
		config := &BootstrapConfig{
			IUnderstandSecurityRisks: true,
			AdminUserID:              "admin",
			AdminOrgID:               "org",
			RecoveryPath:             "/nonexistent/path/recovery.txt", // Invalid path
		}
		_, bootstrap, _ := setupBootstrapTest(t, config)

		// Bootstrap should succeed even though recovery file write fails
		apiKey, err := bootstrap.Bootstrap(context.Background())

		require.NoError(t, err, "bootstrap should succeed even if recovery file write fails")
		require.NotEmpty(t, apiKey.APIKey)
	})
}

// =============================================================================
// Test Helpers
// =============================================================================

// setupBootstrapTest creates a service and bootstrap config for testing
func setupBootstrapTest(t *testing.T, config *BootstrapConfig) (*APIKeyService, *BootstrapService, *mockRepository) {
	t.Helper()

	repo := newMockRepository()
	logger := zaptest.NewLogger(t)
	service, err := NewAPIKeyService(repo, logger, "gak_", 32, 0, 0)
	require.NoError(t, err)

	if config == nil {
		config = &BootstrapConfig{
			IUnderstandSecurityRisks:   true,
			AllowBootstrapInProduction: false,
			AdminUserID:                "test-admin",
			AdminOrgID:                 "test-org",
			AdminEmail:                 "admin@test.com",
		}
	}

	bootstrap := NewBootstrapService(service, config, logger)
	return service, bootstrap, repo
}
