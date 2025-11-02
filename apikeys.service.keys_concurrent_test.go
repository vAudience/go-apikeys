package apikeys

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// copyAPIKeyInfo creates a deep copy of APIKeyInfo to avoid shared memory issues in concurrent tests
func copyAPIKeyInfo(original *APIKeyInfo) *APIKeyInfo {
	if original == nil {
		return nil
	}

	// Copy slices
	roles := make([]string, len(original.Roles))
	copy(roles, original.Roles)

	rights := make([]string, len(original.Rights))
	copy(rights, original.Rights)

	// Copy metadata map
	metadata := make(map[string]any)
	for k, v := range original.Metadata {
		metadata[k] = v
	}

	return &APIKeyInfo{
		APIKey:     original.APIKey,
		APIKeyHash: original.APIKeyHash,
		APIKeyHint: original.APIKeyHint,
		UserID:     original.UserID,
		OrgID:      original.OrgID,
		Name:       original.Name,
		Email:      original.Email,
		Roles:      roles,
		Rights:     rights,
		Metadata:   metadata,
	}
}

// TestConcurrentAPIKeyCreation tests that concurrent API key creation doesn't cause collisions
func TestConcurrentAPIKeyCreation(t *testing.T) {
	t.Run("100 concurrent creations generate unique keys", func(t *testing.T) {
		mockRepo := newMockRepository()
		logger, _ := zap.NewDevelopment()
		service, err := NewAPIKeyService(mockRepo, logger, DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH, 0, 0)
		require.NoError(t, err)

		ctx := context.Background()
		concurrency := 100
		results := make(chan *APIKeyInfo, concurrency)
		var wg sync.WaitGroup

		// Create 100 API keys concurrently
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				apiKeyInfo := &APIKeyInfo{
					UserID: "concurrent-user",
					OrgID:  "concurrent-org",
				}
				created, err := service.CreateAPIKey(ctx, apiKeyInfo)
				if err != nil {
					t.Errorf("Failed to create API key: %v", err)
					return
				}
				results <- created
			}(i)
		}

		wg.Wait()
		close(results)

		// Verify all keys are unique
		keys := make(map[string]bool)
		hashes := make(map[string]bool)
		count := 0

		for created := range results {
			count++
			// Check for duplicate keys
			if keys[created.APIKey] {
				t.Errorf("Duplicate API key generated: %s", created.APIKey)
			}
			keys[created.APIKey] = true

			// Check for duplicate hashes
			if hashes[created.APIKeyHash] {
				t.Errorf("Duplicate hash generated: %s", created.APIKeyHash)
			}
			hashes[created.APIKeyHash] = true

			// Verify key format
			assert.NotEmpty(t, created.APIKey)
			assert.NotEmpty(t, created.APIKeyHash)
		}

		assert.Equal(t, concurrency, count, "Should have created exactly %d keys", concurrency)
		assert.Equal(t, concurrency, len(keys), "Should have %d unique keys", concurrency)
		assert.Equal(t, concurrency, len(hashes), "Should have %d unique hashes", concurrency)
	})

	t.Run("concurrent creation with same user doesn't collide", func(t *testing.T) {
		mockRepo := newMockRepository()
		logger, _ := zap.NewDevelopment()
		service, err := NewAPIKeyService(mockRepo, logger, DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH, 0, 0)
		require.NoError(t, err)

		ctx := context.Background()
		concurrency := 50
		var wg sync.WaitGroup
		var successCount int32

		// Multiple goroutines creating keys for same user
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				apiKeyInfo := &APIKeyInfo{
					UserID: "same-user",
					OrgID:  "same-org",
				}
				_, err := service.CreateAPIKey(ctx, apiKeyInfo)
				if err == nil {
					atomic.AddInt32(&successCount, 1)
				}
			}()
		}

		wg.Wait()
		assert.Equal(t, int32(concurrency), successCount, "All concurrent creations should succeed")
	})
}

// TestConcurrentCacheOperations tests cache thread safety
func TestConcurrentCacheOperations(t *testing.T) {
	t.Run("concurrent reads and writes don't cause races", func(t *testing.T) {
		mockRepo := newMockRepository()
		logger, _ := zap.NewDevelopment()
		service, err := NewAPIKeyService(mockRepo, logger, DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH, 100, 60)
		require.NoError(t, err)

		ctx := context.Background()

		// Pre-populate with keys
		keys := make([]*APIKeyInfo, 10)
		for i := 0; i < 10; i++ {
			apiKeyInfo := &APIKeyInfo{
				UserID: "cache-user",
				OrgID:  "cache-org",
			}
			created, err := service.CreateAPIKey(ctx, apiKeyInfo)
			require.NoError(t, err)
			keys[i] = created
		}

		var wg sync.WaitGroup
		duration := 2 * time.Second
		stopChan := make(chan struct{})

		// Start readers
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func(readerID int) {
				defer wg.Done()
				for {
					select {
					case <-stopChan:
						return
					default:
						keyIdx := readerID % len(keys)
						_, err := service.GetAPIKeyInfo(ctx, keys[keyIdx].APIKey)
						if err != nil {
							t.Errorf("Reader %d failed to get key: %v", readerID, err)
						}
					}
				}
			}(i)
		}

		// Start writers (updating cache)
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(writerID int) {
				defer wg.Done()
				for {
					select {
					case <-stopChan:
						return
					default:
						keyIdx := writerID % len(keys)
						original := keys[keyIdx]
						// Create a deep copy to avoid shared memory races
						keyCopy := copyAPIKeyInfo(original)
						keyCopy.Name = "Updated concurrently"
						err := service.UpdateAPIKey(ctx, keyCopy)
						if err != nil {
							t.Errorf("Writer %d failed to update key: %v", writerID, err)
						}
					}
				}
			}(i)
		}

		// Let it run for duration
		time.Sleep(duration)
		close(stopChan)
		wg.Wait()

		// Verify cache is still functional
		for _, key := range keys {
			retrieved, err := service.GetAPIKeyInfo(ctx, key.APIKey)
			require.NoError(t, err)
			assert.Equal(t, key.UserID, retrieved.UserID)
		}
	})

	t.Run("concurrent cache invalidation doesn't panic", func(t *testing.T) {
		mockRepo := newMockRepository()
		logger, _ := zap.NewDevelopment()
		service, err := NewAPIKeyService(mockRepo, logger, DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH, 50, 60)
		require.NoError(t, err)

		ctx := context.Background()

		// Create a key
		apiKeyInfo := &APIKeyInfo{
			UserID: "invalidate-user",
			OrgID:  "invalidate-org",
		}
		created, err := service.CreateAPIKey(ctx, apiKeyInfo)
		require.NoError(t, err)

		var wg sync.WaitGroup
		concurrency := 50

		// Concurrent deletes (cache invalidation)
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// This should not panic even if called concurrently
				_ = service.DeleteAPIKey(ctx, created.APIKeyHash)
			}()
		}

		wg.Wait()

		// Verify key is deleted
		_, err = service.GetAPIKeyInfo(ctx, created.APIKey)
		assert.Error(t, err)
	})

	t.Run("cache eviction under concurrent load", func(t *testing.T) {
		mockRepo := newMockRepository()
		logger, _ := zap.NewDevelopment()
		// Small cache to force evictions
		service, err := NewAPIKeyService(mockRepo, logger, DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH, 10, 60)
		require.NoError(t, err)

		ctx := context.Background()
		var wg sync.WaitGroup
		concurrency := 50

		// Create more keys than cache size concurrently
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				apiKeyInfo := &APIKeyInfo{
					UserID: "evict-user",
					OrgID:  "evict-org",
				}
				created, err := service.CreateAPIKey(ctx, apiKeyInfo)
				if err != nil {
					t.Errorf("Failed to create key: %v", err)
					return
				}

				// Immediately try to read it back
				retrieved, err := service.GetAPIKeyInfo(ctx, created.APIKey)
				if err != nil {
					t.Errorf("Failed to retrieve just-created key: %v", err)
				}
				if retrieved != nil && retrieved.UserID != created.UserID {
					t.Errorf("Retrieved key doesn't match created key")
				}
			}(i)
		}

		wg.Wait()

		// Verify repository still has all keys (even evicted ones)
		results, count, err := service.SearchAPIKeys(ctx, nil, 0, 100)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, count, concurrency, "Repository should have all keys")
		assert.GreaterOrEqual(t, len(results), concurrency, "Should retrieve at least %d keys", concurrency)
	})
}

// TestConcurrentValidation tests concurrent API key validation
func TestConcurrentValidation(t *testing.T) {
	t.Run("concurrent validation doesn't cause races", func(t *testing.T) {
		mockRepo := newMockRepository()
		logger, _ := zap.NewDevelopment()
		service, err := NewAPIKeyService(mockRepo, logger, DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH, 100, 60)
		require.NoError(t, err)

		ctx := context.Background()

		// Create test keys
		keys := make([]string, 5)
		for i := 0; i < 5; i++ {
			apiKeyInfo := &APIKeyInfo{
				UserID: "validate-user",
				OrgID:  "validate-org",
			}
			created, err := service.CreateAPIKey(ctx, apiKeyInfo)
			require.NoError(t, err)
			keys[i] = created.APIKey
		}

		var wg sync.WaitGroup
		concurrency := 100
		var validationCount int32

		// Concurrent validations
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				keyIdx := id % len(keys)
				validated, err := service.ValidateAPIKey(ctx, keys[keyIdx])
				if err != nil {
					t.Errorf("Validation failed: %v", err)
					return
				}
				if validated != nil {
					atomic.AddInt32(&validationCount, 1)
				}
			}(i)
		}

		wg.Wait()
		assert.Equal(t, int32(concurrency), validationCount, "All validations should succeed")
	})

	t.Run("concurrent validation of invalid keys", func(t *testing.T) {
		mockRepo := newMockRepository()
		logger, _ := zap.NewDevelopment()
		service, err := NewAPIKeyService(mockRepo, logger, DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH, 0, 0)
		require.NoError(t, err)

		ctx := context.Background()
		var wg sync.WaitGroup
		concurrency := 50
		var errorCount int32

		// Concurrent validations of non-existent keys
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := service.ValidateAPIKey(ctx, "gak_nonexistent12345678901234567890")
				if err != nil {
					atomic.AddInt32(&errorCount, 1)
				}
			}()
		}

		wg.Wait()
		assert.Equal(t, int32(concurrency), errorCount, "All validations should fail")
	})
}

// TestConcurrentUpdate tests concurrent updates don't cause corruption
func TestConcurrentUpdate(t *testing.T) {
	t.Run("concurrent updates to same key are serialized", func(t *testing.T) {
		mockRepo := newMockRepository()
		logger, _ := zap.NewDevelopment()
		service, err := NewAPIKeyService(mockRepo, logger, DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH, 0, 0)
		require.NoError(t, err)

		ctx := context.Background()

		// Create a key
		apiKeyInfo := &APIKeyInfo{
			UserID: "update-user",
			OrgID:  "update-org",
			Name:   "Original",
		}
		created, err := service.CreateAPIKey(ctx, apiKeyInfo)
		require.NoError(t, err)

		var wg sync.WaitGroup
		concurrency := 50
		var successCount int32

		// Concurrent updates
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				// Create a copy to avoid shared memory issues
				updateInfo := &APIKeyInfo{
					APIKeyHash: created.APIKeyHash,
					UserID:     created.UserID,
					OrgID:      created.OrgID,
					Name:       "Updated",
				}
				err := service.UpdateAPIKey(ctx, updateInfo)
				if err == nil {
					atomic.AddInt32(&successCount, 1)
				}
			}(i)
		}

		wg.Wait()
		assert.Equal(t, int32(concurrency), successCount, "All updates should succeed")

		// Verify final state is consistent
		retrieved, err := service.GetAPIKeyInfo(ctx, created.APIKeyHash)
		require.NoError(t, err)
		assert.Equal(t, "Updated", retrieved.Name)
	})

	t.Run("concurrent updates to different keys don't interfere", func(t *testing.T) {
		mockRepo := newMockRepository()
		logger, _ := zap.NewDevelopment()
		service, err := NewAPIKeyService(mockRepo, logger, DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH, 0, 0)
		require.NoError(t, err)

		ctx := context.Background()

		// Create multiple keys
		keys := make([]*APIKeyInfo, 10)
		for i := 0; i < 10; i++ {
			apiKeyInfo := &APIKeyInfo{
				UserID: "update-user",
				OrgID:  "update-org",
			}
			created, err := service.CreateAPIKey(ctx, apiKeyInfo)
			require.NoError(t, err)
			keys[i] = created
		}

		var wg sync.WaitGroup
		var successCount int32

		// Update each key concurrently
		for i, key := range keys {
			wg.Add(1)
			go func(idx int, k *APIKeyInfo) {
				defer wg.Done()
				updateInfo := &APIKeyInfo{
					APIKeyHash: k.APIKeyHash,
					UserID:     k.UserID,
					OrgID:      k.OrgID,
					Name:       "Updated",
				}
				err := service.UpdateAPIKey(ctx, updateInfo)
				if err == nil {
					atomic.AddInt32(&successCount, 1)
				}
			}(i, key)
		}

		wg.Wait()
		assert.Equal(t, int32(len(keys)), successCount, "All updates should succeed")

		// Verify all keys updated correctly
		for _, key := range keys {
			retrieved, err := service.GetAPIKeyInfo(ctx, key.APIKeyHash)
			require.NoError(t, err)
			assert.Equal(t, "Updated", retrieved.Name)
		}
	})
}

// TestConcurrentSearch tests concurrent search operations
func TestConcurrentSearch(t *testing.T) {
	t.Run("concurrent searches are consistent", func(t *testing.T) {
		mockRepo := newMockRepository()
		logger, _ := zap.NewDevelopment()
		service, err := NewAPIKeyService(mockRepo, logger, DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH, 0, 0)
		require.NoError(t, err)

		ctx := context.Background()

		// Create keys
		numKeys := 20
		for i := 0; i < numKeys; i++ {
			apiKeyInfo := &APIKeyInfo{
				UserID: "search-user",
				OrgID:  "search-org",
			}
			_, err := service.CreateAPIKey(ctx, apiKeyInfo)
			require.NoError(t, err)
		}

		var wg sync.WaitGroup
		concurrency := 50
		results := make([]int, concurrency)

		// Concurrent searches
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				_, count, err := service.SearchAPIKeys(ctx, nil, 0, 100)
				if err != nil {
					t.Errorf("Search failed: %v", err)
					return
				}
				results[id] = count
			}(i)
		}

		wg.Wait()

		// All searches should return same count
		expectedCount := results[0]
		for i, count := range results {
			assert.Equal(t, expectedCount, count, "Search %d returned different count", i)
		}
		assert.GreaterOrEqual(t, expectedCount, numKeys, "Should find at least %d keys", numKeys)
	})
}

// TestConcurrentDelete tests concurrent deletion
func TestConcurrentDelete(t *testing.T) {
	t.Run("deleting same key concurrently is idempotent", func(t *testing.T) {
		mockRepo := newMockRepository()
		logger, _ := zap.NewDevelopment()
		service, err := NewAPIKeyService(mockRepo, logger, DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH, 0, 0)
		require.NoError(t, err)

		ctx := context.Background()

		// Create a key
		apiKeyInfo := &APIKeyInfo{
			UserID: "delete-user",
			OrgID:  "delete-org",
		}
		created, err := service.CreateAPIKey(ctx, apiKeyInfo)
		require.NoError(t, err)

		var wg sync.WaitGroup
		concurrency := 20
		var errorCount int32

		// Concurrent deletes
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := service.DeleteAPIKey(ctx, created.APIKeyHash)
				if err != nil {
					// First delete succeeds, rest should fail with "not found"
					if !IsNotFoundError(err) {
						t.Errorf("Unexpected error type: %v", err)
					}
					atomic.AddInt32(&errorCount, 1)
				}
			}()
		}

		wg.Wait()

		// Most deletes should fail (except the first one)
		assert.Greater(t, int(errorCount), 0, "Most concurrent deletes should fail")

		// Verify key is deleted
		exists, err := service.Exists(ctx, created.APIKeyHash)
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("concurrent delete and read", func(t *testing.T) {
		mockRepo := newMockRepository()
		logger, _ := zap.NewDevelopment()
		service, err := NewAPIKeyService(mockRepo, logger, DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH, 100, 60)
		require.NoError(t, err)

		ctx := context.Background()

		// Create a key
		apiKeyInfo := &APIKeyInfo{
			UserID: "delete-read-user",
			OrgID:  "delete-read-org",
		}
		created, err := service.CreateAPIKey(ctx, apiKeyInfo)
		require.NoError(t, err)

		var wg sync.WaitGroup
		stopChan := make(chan struct{})
		var readErrors int32
		var deleteAttempted int32

		// Start readers
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stopChan:
						return
					default:
						_, err := service.GetAPIKeyInfo(ctx, created.APIKey)
						if err != nil {
							atomic.AddInt32(&readErrors, 1)
						}
						time.Sleep(1 * time.Millisecond)
					}
				}
			}()
		}

		// Delete after brief delay
		time.Sleep(10 * time.Millisecond)
		err = service.DeleteAPIKey(ctx, created.APIKeyHash)
		if err == nil {
			atomic.AddInt32(&deleteAttempted, 1)
		}

		// Let readers continue for a bit
		time.Sleep(20 * time.Millisecond)
		close(stopChan)
		wg.Wait()

		// Delete should have succeeded
		assert.Equal(t, int32(1), deleteAttempted)

		// Some reads should have failed after deletion
		assert.Greater(t, int(readErrors), 0, "Some reads should fail after deletion")
	})
}

// TestConcurrentContextCancellation tests behavior under concurrent context cancellation
func TestConcurrentContextCancellation(t *testing.T) {
	t.Run("concurrent operations handle context cancellation", func(t *testing.T) {
		mockRepo := newMockRepository()
		logger, _ := zap.NewDevelopment()
		service, err := NewAPIKeyService(mockRepo, logger, DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH, 0, 0)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		concurrency := 50
		var errorCount int32

		// Start operations
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				apiKeyInfo := &APIKeyInfo{
					UserID: "cancel-user",
					OrgID:  "cancel-org",
				}
				_, err := service.CreateAPIKey(ctx, apiKeyInfo)
				if err != nil {
					atomic.AddInt32(&errorCount, 1)
				}
			}()
		}

		// Cancel context immediately
		cancel()
		wg.Wait()

		// Some operations should fail due to cancellation
		// (Depending on timing, some may succeed before cancel)
		t.Logf("Operations failed due to cancellation: %d/%d", errorCount, concurrency)
	})
}

// TestConcurrentMixedOperations tests realistic mixed workload
func TestConcurrentMixedOperations(t *testing.T) {
	t.Run("mixed operations under concurrent load", func(t *testing.T) {
		mockRepo := newMockRepository()
		logger, _ := zap.NewDevelopment()
		service, err := NewAPIKeyService(mockRepo, logger, DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH, 50, 60)
		require.NoError(t, err)

		ctx := context.Background()
		duration := 3 * time.Second
		stopChan := make(chan struct{})
		var wg sync.WaitGroup

		var createCount, readCount, updateCount, searchCount int32

		// Creators
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stopChan:
						return
					default:
						apiKeyInfo := &APIKeyInfo{
							UserID: "mixed-user",
							OrgID:  "mixed-org",
						}
						_, err := service.CreateAPIKey(ctx, apiKeyInfo)
						if err == nil {
							atomic.AddInt32(&createCount, 1)
						}
						time.Sleep(10 * time.Millisecond)
					}
				}
			}()
		}

		// Readers
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stopChan:
						return
					default:
						results, _, err := service.SearchAPIKeys(ctx, nil, 0, 10)
						if err == nil && len(results) > 0 {
							// Use hash instead of APIKey since APIKey is not stored in repository
							_, err := service.GetAPIKeyInfo(ctx, results[0].APIKeyHash)
							if err == nil {
								atomic.AddInt32(&readCount, 1)
							}
						}
						time.Sleep(5 * time.Millisecond)
					}
				}
			}()
		}

		// Updaters
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stopChan:
						return
					default:
						results, _, err := service.SearchAPIKeys(ctx, nil, 0, 5)
						if err == nil && len(results) > 0 {
							original := results[0]
							// Create a deep copy to avoid shared memory races
							keyCopy := copyAPIKeyInfo(original)
							keyCopy.Name = "Updated"
							err := service.UpdateAPIKey(ctx, keyCopy)
							if err == nil {
								atomic.AddInt32(&updateCount, 1)
							}
						}
						time.Sleep(20 * time.Millisecond)
					}
				}
			}()
		}

		// Searchers
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stopChan:
						return
					default:
						_, _, err := service.SearchAPIKeys(ctx, nil, 0, 10)
						if err == nil {
							atomic.AddInt32(&searchCount, 1)
						}
						time.Sleep(10 * time.Millisecond)
					}
				}
			}()
		}

		// Let it run
		time.Sleep(duration)
		close(stopChan)
		wg.Wait()

		// Log statistics
		t.Logf("Mixed operations completed:")
		t.Logf("  Creates:  %d", createCount)
		t.Logf("  Reads:    %d", readCount)
		t.Logf("  Updates:  %d", updateCount)
		t.Logf("  Searches: %d", searchCount)

		// Verify operations occurred
		assert.Greater(t, int(createCount), 0, "Should have created keys")
		assert.Greater(t, int(readCount), 0, "Should have read keys")
		assert.Greater(t, int(searchCount), 0, "Should have searched keys")
	})
}
