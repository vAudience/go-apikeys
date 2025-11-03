// Package apikeys provides API key authentication and management middleware for Go applications.
//
// This file contains the business logic service for API key CRUD operations.
// Following clean architecture, this service is independent of HTTP frameworks.
package apikeys

import (
	"context"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"go.uber.org/zap"
)

// cacheEntry wraps APIKeyInfo with expiration time for TTL support
type cacheEntry struct {
	apiKey    *APIKeyInfo
	expiresAt time.Time
}

// APIKeyService handles business logic for API key operations.
// This service is framework-agnostic and can be used with any HTTP framework.
type APIKeyService struct {
	repo          APIKeyRepository
	logger        *zap.Logger
	apiKeyPrefix  string
	apiKeyLength  int
	cache         *lru.Cache[string, *cacheEntry] // LRU cache for API key lookups
	cacheTTL      time.Duration                   // TTL for cache entries
	observability *Observability                  // Observability features (metrics, audit, tracing)
}

// NewAPIKeyService creates a new API key service.
// cacheSize: Set to 0 to disable caching. Use DEFAULT_CACHE_SIZE (1000) for default.
// cacheTTL: Cache TTL in seconds. Use DEFAULT_CACHE_TTL (300) for default.
func NewAPIKeyService(repo APIKeyRepository, logger *zap.Logger, prefix string, length int, cacheSize int, cacheTTL int) (*APIKeyService, error) {
	if repo == nil {
		return nil, ErrRepositoryRequired
	}
	if logger == nil {
		logger, _ = zap.NewProduction() // Fallback to default logger
	}

	service := &APIKeyService{
		repo:         repo,
		logger:       logger.Named(CLASS_APIKEY_SERVICE),
		apiKeyPrefix: prefix,
		apiKeyLength: length,
		cacheTTL:     time.Duration(cacheTTL) * time.Second,
	}

	// Initialize cache if size > 0
	if cacheSize > 0 {
		cache, err := lru.New[string, *cacheEntry](cacheSize)
		if err != nil {
			logger.Warn("Failed to initialize cache, continuing without caching",
				zap.Error(err),
				zap.Int("cache_size", cacheSize))
		} else {
			service.cache = cache
			logger.Info("API key cache initialized",
				zap.Int("size", cacheSize),
				zap.Int("ttl_seconds", cacheTTL))
		}
	} else {
		logger.Info("API key caching disabled")
	}

	return service, nil
}

// SetObservability injects observability features into the service.
// This is called by APIKeyManager after initialization.
func (s *APIKeyService) SetObservability(obs *Observability) {
	if obs == nil {
		obs = NewObservability(nil, nil, nil) // Use no-op providers
	}
	s.observability = obs
}

// extractActorInfo extracts actor information from context.
// Returns ActorInfo with whatever details are available from the authenticated API key in context.
func (s *APIKeyService) extractActorInfo(ctx context.Context) ActorInfo {
	actor := ActorInfo{}

	// Try to get authenticated API key info from context (set by middleware)
	if value := ctx.Value(contextKeyAPIKeyInfo); value != nil {
		if apiKeyInfo, ok := value.(*APIKeyInfo); ok && apiKeyInfo != nil {
			actor.UserID = apiKeyInfo.UserID
			actor.OrgID = apiKeyInfo.OrgID
			actor.APIKeyHash = apiKeyInfo.APIKeyHash
		}
	}

	return actor
}

// CreateAPIKey creates a new API key with the given information.
// If apiKeyInfo.APIKey is provided, it uses that key; otherwise generates a new one.
// Returns the created APIKeyInfo with the plain-text API key (only time it's returned).
func (s *APIKeyService) CreateAPIKey(ctx context.Context, apiKeyInfo *APIKeyInfo) (*APIKeyInfo, error) {
	// Start operation timing for metrics
	startTime := time.Now()
	actor := s.extractActorInfo(ctx)

	// Validate input
	if apiKeyInfo == nil {
		return nil, NewValidationError("api_key_info", "cannot be nil")
	}

	// Sanitize and validate
	SanitizeAPIKeyInfo(apiKeyInfo)
	if err := ValidateAPIKeyInfo(apiKeyInfo); err != nil {
		s.logger.Warn("API key validation failed",
			zap.String(LOG_FIELD_USER_ID, apiKeyInfo.UserID),
			zap.Error(err))

		// Record validation error metrics
		if s.observability != nil {
			s.observability.Metrics.RecordOperationError(ctx, "create_key", "validation_error")
		}

		return nil, err
	}

	// Generate or use provided API key
	var apiKey string
	var err error
	if apiKeyInfo.APIKey != "" {
		// Use provided API key
		apiKey = apiKeyInfo.APIKey
		s.logger.Debug("Using provided API key",
			zap.String(LOG_FIELD_USER_ID, apiKeyInfo.UserID))
	} else {
		// Generate new API key
		apiKey, err = GenerateAPIKey(s.apiKeyPrefix, s.apiKeyLength)
		if err != nil {
			s.logger.Error("Failed to generate API key",
				zap.String(LOG_FIELD_USER_ID, apiKeyInfo.UserID),
				zap.Error(err))
			return nil, NewInternalError("api_key_generation", err)
		}
	}

	// Generate hash and hint
	hash, hint, err := GenerateAPIKeyHash(apiKey)
	if err != nil {
		s.logger.Error("Failed to generate API key hash",
			zap.String(LOG_FIELD_USER_ID, apiKeyInfo.UserID),
			zap.Error(err))

		// Record error metrics
		if s.observability != nil {
			s.observability.Metrics.RecordOperationError(ctx, "create_key", "hash_generation_error")
		}

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
			zap.String(LOG_FIELD_USER_ID, apiKeyInfo.UserID),
			zap.String(LOG_FIELD_ORG_ID, apiKeyInfo.OrgID),
			zap.Error(err))

		// Record error metrics and audit
		if s.observability != nil {
			s.observability.Metrics.RecordOperationError(ctx, "create_key", "repository_error")

			// Log failure audit event
			event := &KeyLifecycleEvent{
				BaseAuditEvent: NewBaseAuditEvent(
					EventTypeKeyCreated,
					actor,
					ResourceInfo{Type: "api_key", ID: hash},
					OutcomeFailure,
				),
				Operation:    "create",
				TargetUserID: apiKeyInfo.UserID,
				TargetOrgID:  apiKeyInfo.OrgID,
				AfterState:   ToAuditSanitized(apiKeyInfo),
			}
			s.observability.Audit.LogKeyCreated(ctx, event)
		}

		return nil, err
	}

	s.logger.Info("API key created",
		zap.String(LOG_FIELD_USER_ID, apiKeyInfo.UserID),
		zap.String(LOG_FIELD_ORG_ID, apiKeyInfo.OrgID),
		zap.String(LOG_FIELD_HASH, hash),
		zap.String(LOG_FIELD_HINT, hint))

	// Record success metrics and audit
	if s.observability != nil {
		latency := time.Since(startTime)
		s.observability.Metrics.RecordOperation(ctx, "create_key", latency, map[string]string{
			"org_id": apiKeyInfo.OrgID,
		})

		// Log success audit event
		event := &KeyLifecycleEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeKeyCreated,
				actor,
				ResourceInfo{Type: "api_key", ID: hash, Name: apiKeyInfo.Name},
				OutcomeSuccess,
			),
			Operation:    "create",
			TargetUserID: apiKeyInfo.UserID,
			TargetOrgID:  apiKeyInfo.OrgID,
			AfterState:   ToAuditSanitized(apiKeyInfo),
		}
		s.observability.Audit.LogKeyCreated(ctx, event)
	}

	// Return a copy with the plain API key set (only time caller sees it)
	// We must return a copy to avoid data races - the repository has a pointer
	// to apiKeyInfo, and we can't modify it after storing.
	result := &APIKeyInfo{
		APIKey:     apiKey, // Include plain key for return
		APIKeyHash: apiKeyInfo.APIKeyHash,
		APIKeyHint: apiKeyInfo.APIKeyHint,
		UserID:     apiKeyInfo.UserID,
		OrgID:      apiKeyInfo.OrgID,
		Name:       apiKeyInfo.Name,
		Email:      apiKeyInfo.Email,
		Roles:      append([]string{}, apiKeyInfo.Roles...),
		Rights:     append([]string{}, apiKeyInfo.Rights...),
		Metadata:   make(map[string]any, len(apiKeyInfo.Metadata)),
	}
	// Deep copy metadata
	for k, v := range apiKeyInfo.Metadata {
		result.Metadata[k] = v
	}

	return result, nil
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
			zap.String(LOG_FIELD_HASH, hash))
	} else {
		// It's already a hash
		hash = apiKeyOrHash
		s.logger.Debug("Hash provided for lookup",
			zap.String(LOG_FIELD_HASH, hash))
	}

	// Try cache first if enabled
	if s.cache != nil {
		if entry, ok := s.cache.Get(hash); ok {
			// Check if entry is expired
			if time.Now().Before(entry.expiresAt) {
				s.logger.Debug("API key retrieved from cache",
					zap.String(LOG_FIELD_HASH, hash),
					zap.String(LOG_FIELD_USER_ID, entry.apiKey.UserID))
				return entry.apiKey, nil
			}
			// Entry expired, remove it
			s.cache.Remove(hash)
			s.logger.Debug("Cache entry expired, removed",
				zap.String(LOG_FIELD_HASH, hash))
		}
	}

	// Retrieve from repository (cache miss or disabled)
	apiKeyInfo, err := s.repo.GetByHash(ctx, hash)
	if err != nil {
		if IsNotFoundError(err) {
			s.logger.Debug("API key not found",
				zap.String(LOG_FIELD_HASH, hash))
			return nil, ErrAPIKeyNotFound
		}
		s.logger.Error("Failed to retrieve API key",
			zap.String(LOG_FIELD_HASH, hash),
			zap.Error(err))
		return nil, err
	}

	// Populate cache if enabled
	if s.cache != nil {
		entry := &cacheEntry{
			apiKey:    apiKeyInfo,
			expiresAt: time.Now().Add(s.cacheTTL),
		}
		s.cache.Add(hash, entry)
		s.logger.Debug("API key added to cache",
			zap.String(LOG_FIELD_HASH, hash),
			zap.String(LOG_FIELD_USER_ID, apiKeyInfo.UserID),
			zap.Duration("ttl", s.cacheTTL))
	}

	s.logger.Debug("API key retrieved",
		zap.String(LOG_FIELD_HASH, hash),
		zap.String(LOG_FIELD_USER_ID, apiKeyInfo.UserID))

	return apiKeyInfo, nil
}

// UpdateAPIKey updates an existing API key's information.
// The API key hash cannot be changed - use this to update metadata, roles, etc.
func (s *APIKeyService) UpdateAPIKey(ctx context.Context, apiKeyInfo *APIKeyInfo) error {
	// Start operation timing for metrics
	startTime := time.Now()
	actor := s.extractActorInfo(ctx)

	// Validate input
	if apiKeyInfo == nil {
		return NewValidationError("api_key_info", "cannot be nil")
	}
	if apiKeyInfo.APIKeyHash == "" {
		return NewValidationError("api_key_hash", "is required for updates")
	}

	// Get current state for before/after comparison (best effort)
	var beforeState *APIKeyInfoSanitized
	if currentInfo, err := s.repo.GetByHash(ctx, apiKeyInfo.APIKeyHash); err == nil {
		beforeState = ToAuditSanitized(currentInfo)
	}

	// Create a defensive copy to avoid mutating the caller's data
	// This prevents data races when the same pointer is passed concurrently
	apiKeyInfoCopy := &APIKeyInfo{
		APIKeyHash: apiKeyInfo.APIKeyHash,
		APIKeyHint: apiKeyInfo.APIKeyHint,
		UserID:     apiKeyInfo.UserID,
		OrgID:      apiKeyInfo.OrgID,
		Name:       apiKeyInfo.Name,
		Email:      apiKeyInfo.Email,
		Roles:      append([]string{}, apiKeyInfo.Roles...),
		Rights:     append([]string{}, apiKeyInfo.Rights...),
		Metadata:   make(map[string]any, len(apiKeyInfo.Metadata)),
	}
	// Deep copy metadata
	for k, v := range apiKeyInfo.Metadata {
		apiKeyInfoCopy.Metadata[k] = v
	}

	// Sanitize and validate the copy
	SanitizeAPIKeyInfo(apiKeyInfoCopy)
	if err := ValidateAPIKeyInfo(apiKeyInfoCopy); err != nil {
		s.logger.Warn("API key validation failed",
			zap.String("hash", apiKeyInfoCopy.APIKeyHash),
			zap.Error(err))

		// Record validation error metrics
		if s.observability != nil {
			s.observability.Metrics.RecordOperationError(ctx, "update_key", "validation_error")
		}

		return err
	}

	// Clear the plain API key if somehow provided (should never be stored)
	apiKeyInfoCopy.APIKey = ""

	// Update in repository
	err := s.repo.Update(ctx, apiKeyInfoCopy)
	if err != nil {
		if IsNotFoundError(err) {
			s.logger.Warn("API key not found for update",
				zap.String("hash", apiKeyInfoCopy.APIKeyHash))

			// Record not found error metrics
			if s.observability != nil {
				s.observability.Metrics.RecordOperationError(ctx, "update_key", "not_found")
			}

			return ErrAPIKeyNotFound
		}
		s.logger.Error("Failed to update API key",
			zap.String("hash", apiKeyInfoCopy.APIKeyHash),
			zap.Error(err))

		// Record repository error metrics and audit
		if s.observability != nil {
			s.observability.Metrics.RecordOperationError(ctx, "update_key", "repository_error")

			// Log failure audit event
			event := &KeyLifecycleEvent{
				BaseAuditEvent: NewBaseAuditEvent(
					EventTypeKeyUpdated,
					actor,
					ResourceInfo{Type: "api_key", ID: apiKeyInfoCopy.APIKeyHash},
					OutcomeFailure,
				),
				Operation:    "update",
				TargetUserID: apiKeyInfoCopy.UserID,
				TargetOrgID:  apiKeyInfoCopy.OrgID,
				BeforeState:  beforeState,
				AfterState:   ToAuditSanitized(apiKeyInfoCopy),
			}
			s.observability.Audit.LogKeyUpdated(ctx, event)
		}

		return err
	}

	// Invalidate cache entry
	if s.cache != nil {
		s.cache.Remove(apiKeyInfoCopy.APIKeyHash)
		s.logger.Debug("Cache invalidated after update",
			zap.String("hash", apiKeyInfoCopy.APIKeyHash))
	}

	s.logger.Info("API key updated",
		zap.String("hash", apiKeyInfoCopy.APIKeyHash),
		zap.String("user_id", apiKeyInfoCopy.UserID))

	// Record success metrics and audit
	if s.observability != nil {
		latency := time.Since(startTime)
		s.observability.Metrics.RecordOperation(ctx, "update_key", latency, map[string]string{
			"org_id": apiKeyInfoCopy.OrgID,
		})

		// Log success audit event
		event := &KeyLifecycleEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeKeyUpdated,
				actor,
				ResourceInfo{Type: "api_key", ID: apiKeyInfoCopy.APIKeyHash, Name: apiKeyInfoCopy.Name},
				OutcomeSuccess,
			),
			Operation:    "update",
			TargetUserID: apiKeyInfoCopy.UserID,
			TargetOrgID:  apiKeyInfoCopy.OrgID,
			BeforeState:  beforeState,
			AfterState:   ToAuditSanitized(apiKeyInfoCopy),
		}
		s.observability.Audit.LogKeyUpdated(ctx, event)
	}

	return nil
}

// DeleteAPIKey deletes an API key by its plain key or hash.
func (s *APIKeyService) DeleteAPIKey(ctx context.Context, apiKeyOrHash string) error {
	// Start operation timing for metrics
	startTime := time.Now()
	actor := s.extractActorInfo(ctx)

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

			// Record error metrics
			if s.observability != nil {
				s.observability.Metrics.RecordOperationError(ctx, "delete_key", "hash_generation_error")
			}

			return NewInternalError("hash_generation", err)
		}
	} else {
		// It's already a hash
		hash = apiKeyOrHash
	}

	// Get current state for audit trail (best effort)
	var beforeState *APIKeyInfoSanitized
	var targetUserID, targetOrgID string
	if currentInfo, err := s.repo.GetByHash(ctx, hash); err == nil {
		beforeState = ToAuditSanitized(currentInfo)
		targetUserID = currentInfo.UserID
		targetOrgID = currentInfo.OrgID
	}

	// Delete from repository
	err = s.repo.Delete(ctx, hash)
	if err != nil {
		if IsNotFoundError(err) {
			s.logger.Warn("API key not found for deletion",
				zap.String("hash", hash))

			// Record not found error metrics
			if s.observability != nil {
				s.observability.Metrics.RecordOperationError(ctx, "delete_key", "not_found")
			}

			return ErrAPIKeyNotFound
		}
		s.logger.Error("Failed to delete API key",
			zap.String("hash", hash),
			zap.Error(err))

		// Record repository error metrics and audit
		if s.observability != nil {
			s.observability.Metrics.RecordOperationError(ctx, "delete_key", "repository_error")

			// Log failure audit event
			event := &KeyLifecycleEvent{
				BaseAuditEvent: NewBaseAuditEvent(
					EventTypeKeyDeleted,
					actor,
					ResourceInfo{Type: "api_key", ID: hash},
					OutcomeFailure,
				),
				Operation:    "delete",
				TargetUserID: targetUserID,
				TargetOrgID:  targetOrgID,
				BeforeState:  beforeState,
			}
			s.observability.Audit.LogKeyDeleted(ctx, event)
		}

		return err
	}

	// Invalidate cache entry
	if s.cache != nil {
		s.cache.Remove(hash)
		s.logger.Debug("Cache invalidated after deletion",
			zap.String("hash", hash))
	}

	s.logger.Info("API key deleted",
		zap.String("hash", hash))

	// Record success metrics and audit
	if s.observability != nil {
		latency := time.Since(startTime)
		s.observability.Metrics.RecordOperation(ctx, "delete_key", latency, map[string]string{
			"org_id": targetOrgID,
		})

		// Log success audit event
		event := &KeyLifecycleEvent{
			BaseAuditEvent: NewBaseAuditEvent(
				EventTypeKeyDeleted,
				actor,
				ResourceInfo{Type: "api_key", ID: hash},
				OutcomeSuccess,
			),
			Operation:    "delete",
			TargetUserID: targetUserID,
			TargetOrgID:  targetOrgID,
			BeforeState:  beforeState,
		}
		s.observability.Audit.LogKeyDeleted(ctx, event)
	}

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
