// Package apikeys provides API key authentication and management middleware for Go applications.
//
// This file defines the configuration structure for the API key manager.
package apikeys

import (
	"github.com/itsatony/go-datarepository"
	"go.uber.org/zap"
)

// Config contains all configuration options for the API key manager.
// All fields have sensible defaults except Repository and Framework which are required.
type Config struct {
	// HeaderKey is the HTTP header name to read the API key from.
	// Default: "X-API-Key"
	HeaderKey string

	// ApiKeyPrefix is the prefix for generated API keys (e.g., "gak_").
	// Must be 2-5 lowercase letters.
	// Default: "gak_"
	ApiKeyPrefix string

	// ApiKeyLength is the length of the random string part of the API key.
	// Must be at least 10 characters.
	// Default: 32
	ApiKeyLength int

	// IgnoreApiKeyForRoutePatterns contains regex patterns for routes that should skip API key validation.
	// Example: []string{"/health", "/version", "/public/.*"}
	// Default: empty (all routes require API key)
	IgnoreApiKeyForRoutePatterns []string

	// Repository is the data storage backend for API keys (REQUIRED).
	// Use github.com/itsatony/go-datarepository for Redis, PostgreSQL, etc.
	Repository datarepository.DataRepository

	// SystemAPIKey is an optional super admin API key that bypasses all checks.
	// Use with caution! This is mainly for emergency access.
	// Default: empty (disabled)
	SystemAPIKey string

	// EnableCRUD enables the CRUD HTTP endpoints for API key management.
	// Routes: POST /apikeys, GET /apikeys/{id}, PUT /apikeys/{id}, DELETE /apikeys/{id}
	// Default: false
	EnableCRUD bool

	// EnableRateLimit enables rate limiting based on RateLimitRules.
	// Default: false
	EnableRateLimit bool

	// RateLimitRules defines the rate limiting rules when EnableRateLimit is true.
	// Each rule specifies path patterns, limits, and targets (API key, user, org, IP).
	// Default: empty
	RateLimitRules []RateLimitRule

	// Logger is a zap logger for structured logging.
	// If nil, a default logger will be created.
	// Default: zap.NewProduction()
	Logger *zap.Logger

	// Framework is the HTTP framework adapter (REQUIRED).
	// Use NewFiberFramework(), NewMuxFramework(), or NewStdlibFramework().
	Framework HTTPFramework

	// EnableBootstrap enables the bootstrap API key creation feature.
	// When enabled, allows creating a superadmin key on first startup.
	// Default: false
	EnableBootstrap bool

	// BootstrapConfig contains bootstrap-specific configuration.
	// Only used when EnableBootstrap is true.
	BootstrapConfig *BootstrapConfig
}

// BootstrapConfig contains configuration for bootstrap API key creation.
//
// SECURITY WARNING: Bootstrap mode logs API keys in plain text!
// This is a documented security lapse for initial setup only.
// You must explicitly acknowledge the security implications by setting
// IUnderstandSecurityRisks to true.
type BootstrapConfig struct {
	// IUnderstandSecurityRisks must be explicitly set to true to enable bootstrap.
	// This ensures you acknowledge that bootstrap mode:
	//   1. Logs the API key in PLAIN TEXT to the logger
	//   2. May write the key to a recovery file (if RecoveryPath is set)
	//   3. Should ONLY be used for initial setup
	//   4. Requires you to secure/delete logs after bootstrap
	//
	// Setting this to true confirms you understand these security implications.
	// REQUIRED: Must be true for bootstrap to execute.
	IUnderstandSecurityRisks bool

	// AdminUserID is the user ID for the bootstrap superadmin key.
	// Required when bootstrap is enabled.
	AdminUserID string

	// AdminOrgID is the organization ID for the bootstrap superadmin key.
	// Required when bootstrap is enabled.
	AdminOrgID string

	// AdminEmail is the email for the bootstrap superadmin key (optional).
	AdminEmail string

	// RecoveryPath is the file path to save the recovery key.
	// If empty, recovery file is not created (key only shown in logs).
	// If specified, file will be created with 0600 permissions.
	// Example: "./.apikeys-bootstrap-recovery"
	// Default: empty (no recovery file)
	RecoveryPath string

	// Roles are the roles assigned to the bootstrap key.
	// Default: []string{"superadmin"}
	Roles []string

	// Metadata is additional metadata for the bootstrap key.
	// Default: map[string]any{METADATA_KEY_SYSTEM_ADMIN: true, METADATA_KEY_BOOTSTRAP: true}
	Metadata map[string]any
}

// NewConfig creates a new Config with sensible defaults.
// Repository and Framework must still be set explicitly.
func NewConfig() *Config {
	return &Config{
		HeaderKey:                    DEFAULT_HEADER_KEY,
		ApiKeyPrefix:                 DEFAULT_APIKEY_PREFIX,
		ApiKeyLength:                 DEFAULT_APIKEY_LENGTH,
		IgnoreApiKeyForRoutePatterns: []string{},
		EnableCRUD:                   DEFAULT_CRUD_ENABLED,
		EnableRateLimit:              DEFAULT_RATE_LIMIT_ENABLED,
		EnableBootstrap:              DEFAULT_BOOTSTRAP_ENABLED,
		RateLimitRules:               []RateLimitRule{},
	}
}

// Validate validates the configuration and returns an error if invalid.
// This should be called before using the config to create an APIKeyManager.
func (c *Config) Validate() error {
	return ValidateConfig(c)
}

// ApplyDefaults fills in default values for empty fields.
// This is called automatically by New() but can be called manually if needed.
func (c *Config) ApplyDefaults() {
	if c.HeaderKey == "" {
		c.HeaderKey = DEFAULT_HEADER_KEY
	}
	if c.ApiKeyPrefix == "" {
		c.ApiKeyPrefix = DEFAULT_APIKEY_PREFIX
	}
	if c.ApiKeyLength == 0 {
		c.ApiKeyLength = DEFAULT_APIKEY_LENGTH
	}
	if c.Logger == nil {
		// Create default production logger
		logger, _ := zap.NewProduction()
		c.Logger = logger
	}
	if c.IgnoreApiKeyForRoutePatterns == nil {
		c.IgnoreApiKeyForRoutePatterns = []string{}
	}
	if c.RateLimitRules == nil {
		c.RateLimitRules = []RateLimitRule{}
	}
}

// Clone creates a deep copy of the configuration.
// This is useful for testing or creating multiple managers with similar configs.
func (c *Config) Clone() *Config {
	clone := *c

	// Deep copy slices
	clone.IgnoreApiKeyForRoutePatterns = make([]string, len(c.IgnoreApiKeyForRoutePatterns))
	copy(clone.IgnoreApiKeyForRoutePatterns, c.IgnoreApiKeyForRoutePatterns)

	clone.RateLimitRules = make([]RateLimitRule, len(c.RateLimitRules))
	copy(clone.RateLimitRules, c.RateLimitRules)

	// Deep copy bootstrap config if present
	if c.BootstrapConfig != nil {
		bootstrapClone := *c.BootstrapConfig
		bootstrapClone.Roles = make([]string, len(c.BootstrapConfig.Roles))
		copy(bootstrapClone.Roles, c.BootstrapConfig.Roles)

		bootstrapClone.Metadata = make(map[string]any)
		for k, v := range c.BootstrapConfig.Metadata {
			bootstrapClone.Metadata[k] = v
		}
		clone.BootstrapConfig = &bootstrapClone
	}

	return &clone
}
