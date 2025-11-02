// Package apikeys provides API key authentication and management middleware for Go applications.
//
// This file defines the repository interface for data persistence operations.
// Following clean architecture principles, this abstracts the data layer from business logic.
package apikeys

import (
	"context"
	"encoding/json"

	"github.com/itsatony/go-datarepository"
)

// APIKeyRepository defines the interface for API key data persistence operations.
// Implementations can use Redis, PostgreSQL, MongoDB, or any other storage backend.
//
// All methods are context-aware and return errors following the error patterns in apikeys.errors.go.
type APIKeyRepository interface {
	// Create stores a new API key in the repository.
	// Returns error if the key already exists or storage fails.
	Create(ctx context.Context, apiKeyInfo *APIKeyInfo) error

	// GetByHash retrieves an API key by its hash.
	// Returns ErrNotFound if the key doesn't exist.
	GetByHash(ctx context.Context, hash string) (*APIKeyInfo, error)

	// Update updates an existing API key.
	// Returns ErrNotFound if the key doesn't exist.
	Update(ctx context.Context, apiKeyInfo *APIKeyInfo) error

	// Delete removes an API key by its hash.
	// Returns ErrNotFound if the key doesn't exist.
	Delete(ctx context.Context, hash string) error

	// Search searches for API keys matching the given criteria.
	// Returns a list of matching keys and the total count.
	// Supports pagination via offset and limit.
	Search(ctx context.Context, query map[string]interface{}, offset, limit int) ([]*APIKeyInfo, int, error)

	// Exists checks if an API key exists by its hash.
	// Returns true if it exists, false otherwise.
	Exists(ctx context.Context, hash string) (bool, error)
}

// DataRepositoryAdapter adapts go-datarepository to the APIKeyRepository interface.
// This is the default implementation using the go-datarepository package.
type DataRepositoryAdapter struct {
	repo datarepository.DataRepository
}

// NewDataRepositoryAdapter creates a new adapter for go-datarepository.
func NewDataRepositoryAdapter(repo datarepository.DataRepository) (*DataRepositoryAdapter, error) {
	if repo == nil {
		return nil, ErrRepositoryRequired
	}
	return &DataRepositoryAdapter{
		repo: repo,
	}, nil
}

// Create implements APIKeyRepository.Create
func (a *DataRepositoryAdapter) Create(ctx context.Context, apiKeyInfo *APIKeyInfo) error {
	if apiKeyInfo == nil {
		return NewValidationError("api_key_info", "cannot be nil")
	}

	// Use hash as the identifier
	identifier := datarepository.SimpleIdentifier(apiKeyInfo.APIKeyHash)

	// Upsert (create or replace)
	err := a.repo.Upsert(ctx, identifier, apiKeyInfo)
	if err != nil {
		return NewInternalError("repository_create", err)
	}

	return nil
}

// GetByHash implements APIKeyRepository.GetByHash
func (a *DataRepositoryAdapter) GetByHash(ctx context.Context, hash string) (*APIKeyInfo, error) {
	if hash == "" {
		return nil, NewValidationError("hash", "cannot be empty")
	}

	identifier := datarepository.SimpleIdentifier(hash)
	var apiKeyInfo APIKeyInfo

	err := a.repo.Read(ctx, identifier, &apiKeyInfo)
	if err != nil {
		if datarepository.IsNotFoundError(err) {
			return nil, ErrAPIKeyNotFound
		}
		return nil, NewInternalError("repository_read", err)
	}

	return &apiKeyInfo, nil
}

// Update implements APIKeyRepository.Update
func (a *DataRepositoryAdapter) Update(ctx context.Context, apiKeyInfo *APIKeyInfo) error {
	if apiKeyInfo == nil {
		return NewValidationError("api_key_info", "cannot be nil")
	}

	// Check if exists first
	exists, err := a.Exists(ctx, apiKeyInfo.APIKeyHash)
	if err != nil {
		return err
	}
	if !exists {
		return ErrAPIKeyNotFound
	}

	// Update
	identifier := datarepository.SimpleIdentifier(apiKeyInfo.APIKeyHash)
	err = a.repo.Update(ctx, identifier, apiKeyInfo)
	if err != nil {
		return NewInternalError("repository_update", err)
	}

	return nil
}

// Delete implements APIKeyRepository.Delete
func (a *DataRepositoryAdapter) Delete(ctx context.Context, hash string) error {
	if hash == "" {
		return NewValidationError("hash", "cannot be empty")
	}

	// Check if exists first
	exists, err := a.Exists(ctx, hash)
	if err != nil {
		return err
	}
	if !exists {
		return ErrAPIKeyNotFound
	}

	// Delete
	identifier := datarepository.SimpleIdentifier(hash)
	err = a.repo.Delete(ctx, identifier)
	if err != nil {
		return NewInternalError("repository_delete", err)
	}

	return nil
}

// Search implements APIKeyRepository.Search
func (a *DataRepositoryAdapter) Search(ctx context.Context, query map[string]interface{}, offset, limit int) ([]*APIKeyInfo, int, error) {
	// Use wildcard pattern for search - go-datarepository uses List for wildcard searches
	pattern := "*"

	_, entities, err := a.repo.List(ctx, pattern)
	if err != nil {
		return nil, 0, NewInternalError("repository_search", err)
	}

	// Convert entities to APIKeyInfo
	var apiKeyInfos []*APIKeyInfo
	for _, entity := range entities {
		// Entity is a string JSON representation from the repository
		entityStr, ok := entity.(string)
		if !ok {
			continue // Skip non-string entities
		}

		// Unmarshal the JSON string into APIKeyInfo
		var apiKeyInfo APIKeyInfo
		if err := json.Unmarshal([]byte(entityStr), &apiKeyInfo); err != nil {
			// Skip malformed entries, log in production
			continue
		}

		apiKeyInfos = append(apiKeyInfos, &apiKeyInfo)
	}

	// Apply pagination manually (go-datarepository List doesn't support it)
	start := offset
	end := offset + limit
	if start > len(apiKeyInfos) {
		start = len(apiKeyInfos)
	}
	if end > len(apiKeyInfos) {
		end = len(apiKeyInfos)
	}

	total := len(apiKeyInfos)
	if start < end {
		apiKeyInfos = apiKeyInfos[start:end]
	} else {
		apiKeyInfos = []*APIKeyInfo{}
	}

	return apiKeyInfos, total, nil
}

// Exists implements APIKeyRepository.Exists
func (a *DataRepositoryAdapter) Exists(ctx context.Context, hash string) (bool, error) {
	if hash == "" {
		return false, NewValidationError("hash", "cannot be empty")
	}

	identifier := datarepository.SimpleIdentifier(hash)
	var apiKeyInfo APIKeyInfo

	err := a.repo.Read(ctx, identifier, &apiKeyInfo)
	if err != nil {
		if datarepository.IsNotFoundError(err) {
			return false, nil // Not found is not an error for Exists
		}
		return false, NewInternalError("repository_exists", err)
	}

	return true, nil
}
