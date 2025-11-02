// Package apikeys provides API key authentication and management middleware for Go applications.
//
// This file contains the business logic service for API key CRUD operations.
// Following clean architecture, this service is independent of HTTP frameworks.
package apikeys

import (
	"context"

	"go.uber.org/zap"
)

// APIKeyService handles business logic for API key operations.
// This service is framework-agnostic and can be used with any HTTP framework.
type APIKeyService struct {
	repo         APIKeyRepository
	logger       *zap.Logger
	apiKeyPrefix string
	apiKeyLength int
}

// NewAPIKeyService creates a new API key service.
func NewAPIKeyService(repo APIKeyRepository, logger *zap.Logger, prefix string, length int) (*APIKeyService, error) {
	if repo == nil {
		return nil, ErrRepositoryRequired
	}
	if logger == nil {
		logger, _ = zap.NewProduction() // Fallback to default logger
	}

	return &APIKeyService{
		repo:         repo,
		logger:       logger.Named(CLASS_APIKEY_SERVICE),
		apiKeyPrefix: prefix,
		apiKeyLength: length,
	}, nil
}

// CreateAPIKey creates a new API key with the given information.
// If apiKeyInfo.APIKey is provided, it uses that key; otherwise generates a new one.
// Returns the created APIKeyInfo with the plain-text API key (only time it's returned).
func (s *APIKeyService) CreateAPIKey(ctx context.Context, apiKeyInfo *APIKeyInfo) (*APIKeyInfo, error) {
	// Validate input
	if apiKeyInfo == nil {
		return nil, NewValidationError("api_key_info", "cannot be nil")
	}

	// Sanitize and validate
	SanitizeAPIKeyInfo(apiKeyInfo)
	if err := ValidateAPIKeyInfo(apiKeyInfo); err != nil {
		s.logger.Warn("API key validation failed",
			zap.String("user_id", apiKeyInfo.UserID),
			zap.Error(err))
		return nil, err
	}

	// Generate or use provided API key
	var apiKey string
	var err error
	if apiKeyInfo.APIKey != "" {
		// Use provided API key
		apiKey = apiKeyInfo.APIKey
		s.logger.Debug("Using provided API key",
			zap.String("user_id", apiKeyInfo.UserID))
	} else {
		// Generate new API key
		apiKey, err = GenerateAPIKey(s.apiKeyPrefix, s.apiKeyLength)
		if err != nil {
			s.logger.Error("Failed to generate API key",
				zap.String("user_id", apiKeyInfo.UserID),
				zap.Error(err))
			return nil, NewInternalError("api_key_generation", err)
		}
	}

	// Generate hash and hint
	hash, hint, err := GenerateAPIKeyHash(apiKey)
	if err != nil {
		s.logger.Error("Failed to generate API key hash",
			zap.String("user_id", apiKeyInfo.UserID),
			zap.Error(err))
		return nil, NewInternalError("hash_generation", err)
	}

	// Set hash and hint
	apiKeyInfo.APIKeyHash = hash
	apiKeyInfo.APIKeyHint = hint
	apiKeyInfo.APIKey = "" // Clear before storage (never store plain key!)

	// Store in repository
	err = s.repo.Create(ctx, apiKeyInfo)
	if err != nil {
		s.logger.Error("Failed to create API key",
			zap.String("user_id", apiKeyInfo.UserID),
			zap.String("org_id", apiKeyInfo.OrgID),
			zap.Error(err))
		return nil, err
	}

	// Set the plain API key for return (only time caller sees it)
	apiKeyInfo.APIKey = apiKey

	s.logger.Info("API key created",
		zap.String("user_id", apiKeyInfo.UserID),
		zap.String("org_id", apiKeyInfo.OrgID),
		zap.String("hash", hash),
		zap.String("hint", hint))

	return apiKeyInfo, nil
}

// GetAPIKeyInfo retrieves an API key by its plain key or hash.
// This method accepts both formats for convenience.
func (s *APIKeyService) GetAPIKeyInfo(ctx context.Context, apiKeyOrHash string) (*APIKeyInfo, error) {
	// Validate input
	if apiKeyOrHash == "" {
		return nil, ErrAPIKeyRequired
	}

	var hash string
	var err error

	// Check if it's a plain API key or a hash
	if IsAPIKey(apiKeyOrHash) {
		// It's a plain API key - hash it
		hash, _, err = GenerateAPIKeyHash(apiKeyOrHash)
		if err != nil {
			s.logger.Error("Failed to hash API key",
				zap.Error(err))
			return nil, NewInternalError("hash_generation", err)
		}
		s.logger.Debug("API key provided, hashed for lookup",
			zap.String("hash", hash))
	} else {
		// It's already a hash
		hash = apiKeyOrHash
		s.logger.Debug("Hash provided for lookup",
			zap.String("hash", hash))
	}

	// Retrieve from repository
	apiKeyInfo, err := s.repo.GetByHash(ctx, hash)
	if err != nil {
		if IsNotFoundError(err) {
			s.logger.Debug("API key not found",
				zap.String("hash", hash))
			return nil, ErrAPIKeyNotFound
		}
		s.logger.Error("Failed to retrieve API key",
			zap.String("hash", hash),
			zap.Error(err))
		return nil, err
	}

	s.logger.Debug("API key retrieved",
		zap.String("hash", hash),
		zap.String("user_id", apiKeyInfo.UserID))

	return apiKeyInfo, nil
}

// UpdateAPIKey updates an existing API key's information.
// The API key hash cannot be changed - use this to update metadata, roles, etc.
func (s *APIKeyService) UpdateAPIKey(ctx context.Context, apiKeyInfo *APIKeyInfo) error {
	// Validate input
	if apiKeyInfo == nil {
		return NewValidationError("api_key_info", "cannot be nil")
	}
	if apiKeyInfo.APIKeyHash == "" {
		return NewValidationError("api_key_hash", "is required for updates")
	}

	// Sanitize and validate
	SanitizeAPIKeyInfo(apiKeyInfo)
	if err := ValidateAPIKeyInfo(apiKeyInfo); err != nil {
		s.logger.Warn("API key validation failed",
			zap.String("hash", apiKeyInfo.APIKeyHash),
			zap.Error(err))
		return err
	}

	// Clear the plain API key if somehow provided (should never be stored)
	apiKeyInfo.APIKey = ""

	// Update in repository
	err := s.repo.Update(ctx, apiKeyInfo)
	if err != nil {
		if IsNotFoundError(err) {
			s.logger.Warn("API key not found for update",
				zap.String("hash", apiKeyInfo.APIKeyHash))
			return ErrAPIKeyNotFound
		}
		s.logger.Error("Failed to update API key",
			zap.String("hash", apiKeyInfo.APIKeyHash),
			zap.Error(err))
		return err
	}

	s.logger.Info("API key updated",
		zap.String("hash", apiKeyInfo.APIKeyHash),
		zap.String("user_id", apiKeyInfo.UserID))

	return nil
}

// DeleteAPIKey deletes an API key by its plain key or hash.
func (s *APIKeyService) DeleteAPIKey(ctx context.Context, apiKeyOrHash string) error {
	// Validate input
	if apiKeyOrHash == "" {
		return ErrAPIKeyRequired
	}

	var hash string
	var err error

	// Check if it's a plain API key or a hash
	if IsAPIKey(apiKeyOrHash) {
		// It's a plain API key - hash it
		hash, _, err = GenerateAPIKeyHash(apiKeyOrHash)
		if err != nil {
			s.logger.Error("Failed to hash API key",
				zap.Error(err))
			return NewInternalError("hash_generation", err)
		}
	} else {
		// It's already a hash
		hash = apiKeyOrHash
	}

	// Delete from repository
	err = s.repo.Delete(ctx, hash)
	if err != nil {
		if IsNotFoundError(err) {
			s.logger.Warn("API key not found for deletion",
				zap.String("hash", hash))
			return ErrAPIKeyNotFound
		}
		s.logger.Error("Failed to delete API key",
			zap.String("hash", hash),
			zap.Error(err))
		return err
	}

	s.logger.Info("API key deleted",
		zap.String("hash", hash))

	return nil
}

// SearchAPIKeys searches for API keys with pagination.
// Returns a list of API keys and the total count.
func (s *APIKeyService) SearchAPIKeys(ctx context.Context, query map[string]interface{}, offset, limit int) ([]*APIKeyInfo, int, error) {
	// Validate pagination parameters
	if offset < 0 {
		offset = DEFAULT_QUERY_OFFSET
	}
	if limit <= 0 {
		limit = DEFAULT_QUERY_LIMIT
	}
	if limit > 100 {
		limit = 100 // Max limit
	}

	// Search in repository
	apiKeyInfos, total, err := s.repo.Search(ctx, query, offset, limit)
	if err != nil {
		s.logger.Error("Failed to search API keys",
			zap.Int("offset", offset),
			zap.Int("limit", limit),
			zap.Error(err))
		return nil, 0, NewInternalError("search", err)
	}

	s.logger.Debug("API keys searched",
		zap.Int("offset", offset),
		zap.Int("limit", limit),
		zap.Int("results", len(apiKeyInfos)),
		zap.Int("total", total))

	return apiKeyInfos, total, nil
}

// ValidateAPIKey validates an API key and returns its information if valid.
// This is the main validation method used by middleware.
func (s *APIKeyService) ValidateAPIKey(ctx context.Context, apiKey string) (*APIKeyInfo, error) {
	// Check format
	if err := ValidateAPIKey(apiKey); err != nil {
		s.logger.Debug("Invalid API key format",
			zap.Error(err))
		return nil, err
	}

	// Retrieve from repository
	apiKeyInfo, err := s.GetAPIKeyInfo(ctx, apiKey)
	if err != nil {
		return nil, err
	}

	s.logger.Debug("API key validated",
		zap.String("user_id", apiKeyInfo.UserID),
		zap.String("org_id", apiKeyInfo.OrgID))

	return apiKeyInfo, nil
}

// IsSystemAdmin checks if an API key has system admin privileges.
// This checks the metadata for the system_admin flag.
func (s *APIKeyService) IsSystemAdmin(apiKeyInfo *APIKeyInfo) bool {
	if apiKeyInfo == nil || apiKeyInfo.Metadata == nil {
		return false
	}

	systemAdmin, ok := apiKeyInfo.Metadata[METADATA_KEY_SYSTEM_ADMIN]
	if !ok {
		return false
	}

	isSysAdmin, ok := systemAdmin.(bool)
	if !ok {
		s.logger.Warn("system_admin metadata is not boolean",
			zap.String("user_id", apiKeyInfo.UserID),
			zap.Any("value", systemAdmin))
		return false
	}

	return isSysAdmin
}

// Exists checks if an API key exists by its hash.
func (s *APIKeyService) Exists(ctx context.Context, apiKeyOrHash string) (bool, error) {
	if apiKeyOrHash == "" {
		return false, ErrAPIKeyRequired
	}

	var hash string
	var err error

	if IsAPIKey(apiKeyOrHash) {
		hash, _, err = GenerateAPIKeyHash(apiKeyOrHash)
		if err != nil {
			return false, NewInternalError("hash_generation", err)
		}
	} else {
		hash = apiKeyOrHash
	}

	return s.repo.Exists(ctx, hash)
}
