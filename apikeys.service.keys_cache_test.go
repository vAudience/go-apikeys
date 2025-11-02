// Package apikeys provides API key authentication and management middleware for Go applications.
//
// This file tests the LRU cache functionality for API key lookups.
package apikeys

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// =============================================================================
// Cache Tests (6 tests)
// =============================================================================

func TestAPIKeyService_Cache(t *testing.T) {
	t.Run("cache hit returns cached value", func(t *testing.T) {
		// Setup service with cache enabled
		repo := newMockRepository()
		logger := zaptest.NewLogger(t)
		service, err := NewAPIKeyService(repo, logger, "gak_", 32, 100, 300) // 100 entries, 300s TTL
		require.NoError(t, err)

		ctx := context.Background()

		// Create an API key
		apiKeyInfo := &APIKeyInfo{
			UserID: "cache-user",
			OrgID:  "cache-org",
			Email:  "cache@test.com",
		}
		created, err := service.CreateAPIKey(ctx, apiKeyInfo)
		require.NoError(t, err)

		// First lookup - cache miss (loads from repo)
		retrieved1, err := service.GetAPIKeyInfo(ctx, created.APIKey)
		require.NoError(t, err)
		assert.Equal(t, "cache-user", retrieved1.UserID)

		// Clear the mock repository to verify cache is being used
		repo.data = make(map[string]*APIKeyInfo)

		// Second lookup - cache hit (doesn't need repo)
		retrieved2, err := service.GetAPIKeyInfo(ctx, created.APIKey)
		require.NoError(t, err)
		assert.Equal(t, "cache-user", retrieved2.UserID)
		assert.Equal(t, retrieved1.APIKeyHash, retrieved2.APIKeyHash)
	})

	t.Run("cache miss loads from repository", func(t *testing.T) {
		repo := newMockRepository()
		logger := zaptest.NewLogger(t)
		service, err := NewAPIKeyService(repo, logger, "gak_", 32, 100, 300)
		require.NoError(t, err)

		ctx := context.Background()

		// Create an API key to get a valid hash
		tempKey := &APIKeyInfo{
			UserID: "temp-user",
			OrgID:  "temp-org",
		}
		created, err := service.CreateAPIKey(ctx, tempKey)
		require.NoError(t, err)
		validHash := created.APIKeyHash

		// Clear the cache by creating new service instance
		service, err = NewAPIKeyService(repo, logger, "gak_", 32, 100, 300)
		require.NoError(t, err)

		// Update the data in repo with different user
		repo.data[validHash].UserID = "miss-user"

		// First lookup should be cache miss and load from repo
		retrieved, err := service.GetAPIKeyInfo(ctx, validHash)
		require.NoError(t, err)
		assert.Equal(t, "miss-user", retrieved.UserID)

		// Verify it's now in cache by clearing repo
		repo.data = make(map[string]*APIKeyInfo)

		// Second lookup should be cache hit
		retrieved2, err := service.GetAPIKeyInfo(ctx, validHash)
		require.NoError(t, err)
		assert.Equal(t, "miss-user", retrieved2.UserID)
	})

	t.Run("cache is invalidated on update", func(t *testing.T) {
		repo := newMockRepository()
		logger := zaptest.NewLogger(t)
		service, err := NewAPIKeyService(repo, logger, "gak_", 32, 100, 300)
		require.NoError(t, err)

		ctx := context.Background()

		// Create an API key
		apiKeyInfo := &APIKeyInfo{
			UserID: "update-user",
			OrgID:  "update-org",
			Email:  "update@test.com",
		}
		created, err := service.CreateAPIKey(ctx, apiKeyInfo)
		require.NoError(t, err)

		// Save the API key and hash before update clears them
		apiKey := created.APIKey
		hash := created.APIKeyHash

		// Lookup to populate cache
		_, err = service.GetAPIKeyInfo(ctx, apiKey)
		require.NoError(t, err)

		// Update the API key
		created.Email = "updated@test.com"
		err = service.UpdateAPIKey(ctx, created)
		require.NoError(t, err)

		// Lookup again using hash - should get fresh data from repo (cache invalidated)
		retrieved, err := service.GetAPIKeyInfo(ctx, hash)
		require.NoError(t, err)
		assert.Equal(t, "updated@test.com", retrieved.Email)
	})

	t.Run("cache is invalidated on delete", func(t *testing.T) {
		repo := newMockRepository()
		logger := zaptest.NewLogger(t)
		service, err := NewAPIKeyService(repo, logger, "gak_", 32, 100, 300)
		require.NoError(t, err)

		ctx := context.Background()

		// Create an API key
		apiKeyInfo := &APIKeyInfo{
			UserID: "delete-user",
			OrgID:  "delete-org",
		}
		created, err := service.CreateAPIKey(ctx, apiKeyInfo)
		require.NoError(t, err)

		// Lookup to populate cache
		_, err = service.GetAPIKeyInfo(ctx, created.APIKey)
		require.NoError(t, err)

		// Delete the API key
		err = service.DeleteAPIKey(ctx, created.APIKey)
		require.NoError(t, err)

		// Lookup again - should fail (not found)
		_, err = service.GetAPIKeyInfo(ctx, created.APIKey)
		require.Error(t, err)
		assert.True(t, IsNotFoundError(err))
	})

	t.Run("cache disabled when size is zero", func(t *testing.T) {
		repo := newMockRepository()
		logger := zaptest.NewLogger(t)
		// Create service with cache disabled (size = 0)
		service, err := NewAPIKeyService(repo, logger, "gak_", 32, 0, 300)
		require.NoError(t, err)

		// Verify cache is nil
		assert.Nil(t, service.cache, "cache should be nil when disabled")

		ctx := context.Background()

		// Create an API key
		apiKeyInfo := &APIKeyInfo{
			UserID: "nocache-user",
			OrgID:  "nocache-org",
		}
		created, err := service.CreateAPIKey(ctx, apiKeyInfo)
		require.NoError(t, err)

		// First lookup
		retrieved1, err := service.GetAPIKeyInfo(ctx, created.APIKey)
		require.NoError(t, err)
		assert.Equal(t, "nocache-user", retrieved1.UserID)

		// Clear repo
		repo.data = make(map[string]*APIKeyInfo)

		// Second lookup should fail (no cache to fall back to)
		_, err = service.GetAPIKeyInfo(ctx, created.APIKey)
		require.Error(t, err)
		assert.True(t, IsNotFoundError(err))
	})

	t.Run("cache entries expire after TTL", func(t *testing.T) {
		repo := newMockRepository()
		logger := zaptest.NewLogger(t)
		// Create service with very short TTL (1 second)
		service, err := NewAPIKeyService(repo, logger, "gak_", 32, 100, 1)
		require.NoError(t, err)

		ctx := context.Background()

		// Create an API key
		apiKeyInfo := &APIKeyInfo{
			UserID: "ttl-user",
			OrgID:  "ttl-org",
		}
		created, err := service.CreateAPIKey(ctx, apiKeyInfo)
		require.NoError(t, err)

		// First lookup to populate cache
		retrieved1, err := service.GetAPIKeyInfo(ctx, created.APIKey)
		require.NoError(t, err)
		assert.Equal(t, "ttl-user", retrieved1.UserID)

		// Immediate second lookup should hit cache
		repo.data = make(map[string]*APIKeyInfo)
		retrieved2, err := service.GetAPIKeyInfo(ctx, created.APIKey)
		require.NoError(t, err)
		assert.Equal(t, "ttl-user", retrieved2.UserID)

		// Wait for TTL to expire
		time.Sleep(1100 * time.Millisecond)

		// Third lookup should be cache miss (expired)
		// Since repo is cleared, this should fail
		_, err = service.GetAPIKeyInfo(ctx, created.APIKey)
		require.Error(t, err)
		assert.True(t, IsNotFoundError(err), "should fail because cache expired and repo is empty")
	})
}
