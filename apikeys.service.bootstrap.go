// Package apikeys provides API key authentication and management middleware for Go applications.
//
// This file contains the bootstrap service for creating initial admin API keys.
// SECURITY WARNING: Bootstrap creates keys with clear-text logging - use only for initial setup.
package apikeys

import (
	"context"
	"fmt"
	"os"

	"go.uber.org/zap"
)

// BootstrapService handles bootstrap API key creation
type BootstrapService struct {
	service *APIKeyService
	config  *BootstrapConfig
	logger  *zap.Logger
}

// NewBootstrapService creates a new bootstrap service
func NewBootstrapService(service *APIKeyService, config *BootstrapConfig, logger *zap.Logger) *BootstrapService {
	if config == nil {
		config = &BootstrapConfig{
			AdminUserID: "bootstrap-admin",
			AdminOrgID:  "system",
			AdminEmail:  "admin@system",
			Roles:       []string{"system_admin"},
			Metadata: map[string]any{
				METADATA_KEY_SYSTEM_ADMIN: true,
				METADATA_KEY_CREATED_BY:   "bootstrap",
			},
		}
	}

	return &BootstrapService{
		service: service,
		config:  config,
		logger:  logger.Named(CLASS_BOOTSTRAP_SERVICE),
	}
}

// NeedsBootstrap checks if bootstrap is needed by searching for existing system admin keys
func (b *BootstrapService) NeedsBootstrap(ctx context.Context) (bool, error) {
	// Search for existing API keys
	apiKeys, total, err := b.service.SearchAPIKeys(ctx, nil, 0, 10)
	if err != nil {
		b.logger.Error("Failed to check if bootstrap is needed",
			zap.Error(err))
		return false, NewInternalError("bootstrap_check", err)
	}

	// If no keys exist, bootstrap is needed
	if total == 0 {
		b.logger.Info("No API keys found - bootstrap needed")
		return true, nil
	}

	// Check if any existing key is a system admin
	for _, key := range apiKeys {
		if b.service.IsSystemAdmin(key) {
			b.logger.Info("System admin key exists - bootstrap not needed",
				zap.String(LOG_FIELD_USER_ID, key.UserID))
			return false, nil
		}
	}

	// Keys exist but no system admin
	b.logger.Warn("API keys exist but no system admin found - bootstrap recommended")
	return true, nil
}

// Bootstrap creates an initial system admin API key
// SECURITY WARNING: This logs the API key in clear text - use only for initial setup!
func (b *BootstrapService) Bootstrap(ctx context.Context) (*APIKeyInfo, error) {
	// Safety check: Require explicit security risk acknowledgment
	if !b.config.IUnderstandSecurityRisks {
		b.logger.Error("Bootstrap blocked: security risk acknowledgment required",
			zap.String("required_field", "IUnderstandSecurityRisks"),
			zap.Bool("current_value", b.config.IUnderstandSecurityRisks))
		return nil, NewValidationError("bootstrap_config.i_understand_security_risks",
			"must be true to enable bootstrap - acknowledges that API key will be logged in plain text")
	}

	// Check if bootstrap is needed
	needed, err := b.NeedsBootstrap(ctx)
	if err != nil {
		return nil, err
	}

	if !needed {
		b.logger.Info("Bootstrap not needed - system admin key already exists")
		return nil, NewValidationError("bootstrap", "system admin key already exists")
	}

	// Create bootstrap API key info
	apiKeyInfo := &APIKeyInfo{
		UserID:   b.config.AdminUserID,
		OrgID:    b.config.AdminOrgID,
		Email:    b.config.AdminEmail,
		Name:     "Bootstrap System Admin",
		Roles:    b.config.Roles,
		Metadata: b.config.Metadata,
	}

	// Ensure system_admin metadata is set
	if apiKeyInfo.Metadata == nil {
		apiKeyInfo.Metadata = make(map[string]any)
	}
	apiKeyInfo.Metadata[METADATA_KEY_SYSTEM_ADMIN] = true
	apiKeyInfo.Metadata[METADATA_KEY_CREATED_BY] = "bootstrap"

	// Create the API key
	createdKey, err := b.service.CreateAPIKey(ctx, apiKeyInfo)
	if err != nil {
		b.logger.Error("Failed to create bootstrap API key",
			zap.String(LOG_FIELD_USER_ID, apiKeyInfo.UserID),
			zap.Error(err))
		return nil, err
	}

	// SECURITY WARNING: Log the API key in CLEAR TEXT with strong warning
	b.logger.Warn("╔═══════════════════════════════════════════════════════════════════════════╗")
	b.logger.Warn("║ BOOTSTRAP API KEY CREATED - STORE SECURELY AND DELETE THIS LOG!          ║")
	b.logger.Warn("╠═══════════════════════════════════════════════════════════════════════════╣")
	b.logger.Warn(fmt.Sprintf("║ API Key:  %-63s ║", createdKey.APIKey))
	b.logger.Warn(fmt.Sprintf("║ User ID:  %-63s ║", createdKey.UserID))
	b.logger.Warn(fmt.Sprintf("║ Org ID:   %-63s ║", createdKey.OrgID))
	b.logger.Warn(fmt.Sprintf("║ Hint:     %-63s ║", createdKey.APIKeyHint))
	b.logger.Warn("╠═══════════════════════════════════════════════════════════════════════════╣")
	b.logger.Warn("║ THIS IS A DOCUMENTED SECURITY LAPSE FOR BOOTSTRAP ONLY!                  ║")
	b.logger.Warn("║ 1. Store this key securely                                                ║")
	b.logger.Warn("║ 2. Delete or secure this log file                                         ║")
	b.logger.Warn("║ 3. Create additional admin keys via API                                   ║")
	b.logger.Warn("║ 4. Consider rotating this bootstrap key after setup                       ║")
	b.logger.Warn("╚═══════════════════════════════════════════════════════════════════════════╝")

	// Save to recovery file if configured
	if b.config.RecoveryPath != "" {
		if err := b.saveToRecoveryFile(createdKey); err != nil {
			b.logger.Warn("Failed to save bootstrap key to recovery file",
				zap.String("path", b.config.RecoveryPath),
				zap.Error(err))
			// Don't fail bootstrap if recovery file write fails
		}
	}

	b.logger.Info("Bootstrap API key created successfully",
		zap.String(LOG_FIELD_USER_ID, createdKey.UserID),
		zap.String(LOG_FIELD_HINT, createdKey.APIKeyHint))

	return createdKey, nil
}

// saveToRecoveryFile saves the bootstrap key to a recovery file
func (b *BootstrapService) saveToRecoveryFile(apiKey *APIKeyInfo) error {
	content := fmt.Sprintf(`╔═══════════════════════════════════════════════════════════════════════════╗
║ BOOTSTRAP API KEY RECOVERY FILE                                           ║
║ SECURITY WARNING: Delete this file after storing the key securely!       ║
╠═══════════════════════════════════════════════════════════════════════════╣
║ API Key:  %-63s ║
║ User ID:  %-63s ║
║ Org ID:   %-63s ║
║ Hint:     %-63s ║
║ Hash:     %-63s ║
╚═══════════════════════════════════════════════════════════════════════════╝

Store this key securely and DELETE THIS FILE immediately after.
`,
		apiKey.APIKey,
		apiKey.UserID,
		apiKey.OrgID,
		apiKey.APIKeyHint,
		apiKey.APIKeyHash[:40]+"...", // Truncate hash
	)

	// Write with owner-only permissions (0600)
	err := os.WriteFile(b.config.RecoveryPath, []byte(content), BOOTSTRAP_RECOVERY_FILE_PERMISSIONS)
	if err != nil {
		return NewInternalError("recovery_file_write", err)
	}

	b.logger.Warn("Bootstrap key saved to recovery file",
		zap.String("path", b.config.RecoveryPath))

	return nil
}
