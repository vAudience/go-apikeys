package apikeys

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/itsatony/go-datarepository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock DataRepository
// =============================================================================

type mockDataRepository struct {
	data map[string]string // stores JSON strings

	// Error injection
	createError error
	upsertError error
	readError   error
	updateError error
	deleteError error
	listError   error
	searchError error
}

func newMockDataRepository() *mockDataRepository {
	return &mockDataRepository{
		data: make(map[string]string),
	}
}

func (m *mockDataRepository) Create(ctx context.Context, id datarepository.EntityIdentifier, entity interface{}) error {
	if m.createError != nil {
		return m.createError
	}

	// Check if already exists
	if _, exists := m.data[id.String()]; exists {
		return errors.New("already exists")
	}

	// Serialize to JSON
	jsonBytes, err := json.Marshal(entity)
	if err != nil {
		return err
	}

	m.data[id.String()] = string(jsonBytes)
	return nil
}

func (m *mockDataRepository) Upsert(ctx context.Context, id datarepository.EntityIdentifier, entity interface{}) error {
	if m.upsertError != nil {
		return m.upsertError
	}

	// Serialize to JSON
	jsonBytes, err := json.Marshal(entity)
	if err != nil {
		return err
	}

	m.data[id.String()] = string(jsonBytes)
	return nil
}

func (m *mockDataRepository) Read(ctx context.Context, id datarepository.EntityIdentifier, entity interface{}) error {
	if m.readError != nil {
		return m.readError
	}

	jsonStr, exists := m.data[id.String()]
	if !exists {
		return datarepository.ErrNotFound
	}

	return json.Unmarshal([]byte(jsonStr), entity)
}

func (m *mockDataRepository) Update(ctx context.Context, id datarepository.EntityIdentifier, entity interface{}) error {
	if m.updateError != nil {
		return m.updateError
	}

	// Check if exists
	if _, exists := m.data[id.String()]; !exists {
		return datarepository.ErrNotFound
	}

	// Serialize and update
	jsonBytes, err := json.Marshal(entity)
	if err != nil {
		return err
	}

	m.data[id.String()] = string(jsonBytes)
	return nil
}

func (m *mockDataRepository) Delete(ctx context.Context, id datarepository.EntityIdentifier) error {
	if m.deleteError != nil {
		return m.deleteError
	}

	if _, exists := m.data[id.String()]; !exists {
		return datarepository.ErrNotFound
	}

	delete(m.data, id.String())
	return nil
}

func (m *mockDataRepository) List(ctx context.Context, pattern string) ([]datarepository.EntityIdentifier, []interface{}, error) {
	if m.listError != nil {
		return nil, nil, m.listError
	}

	// Get all keys and sort them for consistent ordering
	var keys []string
	for id := range m.data {
		keys = append(keys, id)
	}
	sort.Strings(keys)

	var ids []datarepository.EntityIdentifier
	var entities []interface{}
	for _, key := range keys {
		ids = append(ids, datarepository.SimpleIdentifier(key))
		entities = append(entities, m.data[key])
	}

	return ids, entities, nil
}

func (m *mockDataRepository) Search(ctx context.Context, query string, offset, limit int, sortBy, sortDir string) ([]datarepository.EntityIdentifier, error) {
	if m.searchError != nil {
		return nil, m.searchError
	}
	// Not used by adapter
	return nil, nil
}

func (m *mockDataRepository) AcquireLock(ctx context.Context, id datarepository.EntityIdentifier, ttl time.Duration) (bool, error) {
	// Not used by adapter
	return true, nil
}

func (m *mockDataRepository) ReleaseLock(ctx context.Context, id datarepository.EntityIdentifier) error {
	// Not used by adapter
	return nil
}

func (m *mockDataRepository) AtomicIncrement(ctx context.Context, id datarepository.EntityIdentifier) (int64, error) {
	// Not used by adapter
	return 1, nil
}

func (m *mockDataRepository) Close() error {
	// Not used by adapter
	return nil
}

func (m *mockDataRepository) Publish(ctx context.Context, channel string, message interface{}) error {
	// Not used by adapter
	return nil
}

func (m *mockDataRepository) Subscribe(ctx context.Context, channel string) (chan interface{}, error) {
	// Not used by adapter
	ch := make(chan interface{})
	close(ch)
	return ch, nil
}

func (m *mockDataRepository) Ping(ctx context.Context) error {
	// Not used by adapter
	return nil
}

func (m *mockDataRepository) SetExpiration(ctx context.Context, id datarepository.EntityIdentifier, expiration time.Duration) error {
	// Not used by adapter
	return nil
}

func (m *mockDataRepository) GetExpiration(ctx context.Context, id datarepository.EntityIdentifier) (time.Duration, error) {
	// Not used by adapter
	return 0, nil
}

func (m *mockDataRepository) RegisterPlugin(plugin datarepository.RepositoryPlugin) error {
	// Not used by adapter
	return nil
}

func (m *mockDataRepository) GetPlugin(name string) (datarepository.RepositoryPlugin, bool) {
	// Not used by adapter
	return nil, false
}

// =============================================================================
// NewDataRepositoryAdapter Tests (2 tests)
// =============================================================================

func TestNewDataRepositoryAdapter(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, err := NewDataRepositoryAdapter(mockRepo)
		assert.NoError(t, err)
		assert.NotNil(t, adapter)
		assert.Equal(t, mockRepo, adapter.repo)
	})

	t.Run("nil repository returns error", func(t *testing.T) {
		adapter, err := NewDataRepositoryAdapter(nil)
		assert.Error(t, err)
		assert.Nil(t, adapter)
		assert.True(t, errors.Is(err, ErrRepositoryRequired))
	})
}

// =============================================================================
// Create Tests (6 tests)
// =============================================================================

func TestDataRepositoryAdapter_Create(t *testing.T) {
	t.Run("successful creation", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		apiKeyInfo := &APIKeyInfo{
			APIKeyHash: "test-hash",
			UserID:     "test-user",
			OrgID:      "test-org",
		}

		err := adapter.Create(ctx, apiKeyInfo)
		assert.NoError(t, err)

		// Verify it was stored
		assert.Contains(t, mockRepo.data, "test-hash")
	})

	t.Run("nil apiKeyInfo returns validation error", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		err := adapter.Create(ctx, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "api_key_info")
		assert.True(t, errors.Is(err, ErrInvalidInput))
	})

	t.Run("repository upsert error", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		mockRepo.upsertError = errors.New("storage failure")
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		apiKeyInfo := &APIKeyInfo{
			APIKeyHash: "test-hash",
			UserID:     "test-user",
			OrgID:      "test-org",
		}

		err := adapter.Create(ctx, apiKeyInfo)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "repository_create")
	})

	t.Run("creates with all fields populated", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		apiKeyInfo := NewTestAPIKeyInfoFull()
		apiKeyInfo.APIKeyHash = "full-hash"

		err := adapter.Create(ctx, apiKeyInfo)
		assert.NoError(t, err)

		// Verify all fields were stored
		var retrieved APIKeyInfo
		mockRepo.Read(ctx, datarepository.SimpleIdentifier("full-hash"), &retrieved)
		assert.Equal(t, apiKeyInfo.UserID, retrieved.UserID)
		assert.Equal(t, apiKeyInfo.Name, retrieved.Name)
		assert.Equal(t, apiKeyInfo.Roles, retrieved.Roles)
	})

	t.Run("overwrites existing key (upsert behavior)", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		// Create first version
		apiKeyInfo1 := &APIKeyInfo{
			APIKeyHash: "test-hash",
			UserID:     "user1",
			OrgID:      "org1",
			Name:       "Original",
		}
		adapter.Create(ctx, apiKeyInfo1)

		// Create second version with same hash
		apiKeyInfo2 := &APIKeyInfo{
			APIKeyHash: "test-hash",
			UserID:     "user2",
			OrgID:      "org2",
			Name:       "Updated",
		}
		err := adapter.Create(ctx, apiKeyInfo2)
		assert.NoError(t, err)

		// Verify it was overwritten
		var retrieved APIKeyInfo
		mockRepo.Read(ctx, datarepository.SimpleIdentifier("test-hash"), &retrieved)
		assert.Equal(t, "user2", retrieved.UserID)
		assert.Equal(t, "Updated", retrieved.Name)
	})

	t.Run("context cancellation", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		apiKeyInfo := &APIKeyInfo{
			APIKeyHash: "test-hash",
			UserID:     "test-user",
			OrgID:      "test-org",
		}

		// Note: mock doesn't check context, but real implementation would
		err := adapter.Create(ctx, apiKeyInfo)
		// In real implementation, this would return context.Canceled
		// For now, just verify method completes
		_ = err
	})
}

// =============================================================================
// GetByHash Tests (6 tests)
// =============================================================================

func TestDataRepositoryAdapter_GetByHash(t *testing.T) {
	t.Run("successful retrieval", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		// Store a key
		apiKeyInfo := &APIKeyInfo{
			APIKeyHash: "test-hash",
			UserID:     "test-user",
			OrgID:      "test-org",
			Name:       "Test Key",
		}
		adapter.Create(ctx, apiKeyInfo)

		// Retrieve it
		retrieved, err := adapter.GetByHash(ctx, "test-hash")
		assert.NoError(t, err)
		assert.NotNil(t, retrieved)
		assert.Equal(t, "test-user", retrieved.UserID)
		assert.Equal(t, "Test Key", retrieved.Name)
	})

	t.Run("empty hash returns validation error", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		retrieved, err := adapter.GetByHash(ctx, "")
		assert.Error(t, err)
		assert.Nil(t, retrieved)
		assert.Contains(t, err.Error(), "hash")
		assert.True(t, errors.Is(err, ErrInvalidInput))
	})

	t.Run("not found returns ErrAPIKeyNotFound", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		retrieved, err := adapter.GetByHash(ctx, "nonexistent")
		assert.Error(t, err)
		assert.Nil(t, retrieved)
		assert.True(t, errors.Is(err, ErrAPIKeyNotFound))
	})

	t.Run("repository read error", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		mockRepo.readError = errors.New("storage read failure")
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		retrieved, err := adapter.GetByHash(ctx, "test-hash")
		assert.Error(t, err)
		assert.Nil(t, retrieved)
		assert.Contains(t, err.Error(), "repository_read")
	})

	t.Run("retrieves all fields correctly", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		// Store complex key
		apiKeyInfo := NewTestAPIKeyInfoFull()
		apiKeyInfo.APIKeyHash = "complex-hash"
		adapter.Create(ctx, apiKeyInfo)

		// Retrieve and verify all fields
		retrieved, err := adapter.GetByHash(ctx, "complex-hash")
		assert.NoError(t, err)
		assert.Equal(t, apiKeyInfo.Roles, retrieved.Roles)
		assert.Equal(t, apiKeyInfo.Rights, retrieved.Rights)
		assert.Equal(t, apiKeyInfo.Metadata, retrieved.Metadata)
	})

	t.Run("JSON deserialization maintains types", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		// Store key with metadata
		apiKeyInfo := &APIKeyInfo{
			APIKeyHash: "type-test",
			UserID:     "user",
			OrgID:      "org",
			Metadata: map[string]any{
				"string": "value",
				"number": float64(123),
				"bool":   true,
			},
		}
		adapter.Create(ctx, apiKeyInfo)

		// Retrieve and check types
		retrieved, err := adapter.GetByHash(ctx, "type-test")
		assert.NoError(t, err)
		assert.IsType(t, "string", retrieved.Metadata["string"])
		assert.IsType(t, float64(0), retrieved.Metadata["number"])
		assert.IsType(t, true, retrieved.Metadata["bool"])
	})
}

// =============================================================================
// Update Tests (7 tests)
// =============================================================================

func TestDataRepositoryAdapter_Update(t *testing.T) {
	t.Run("successful update", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		// Create initial key
		apiKeyInfo := &APIKeyInfo{
			APIKeyHash: "test-hash",
			UserID:     "test-user",
			OrgID:      "test-org",
			Name:       "Original",
		}
		adapter.Create(ctx, apiKeyInfo)

		// Update it
		apiKeyInfo.Name = "Updated"
		err := adapter.Update(ctx, apiKeyInfo)
		assert.NoError(t, err)

		// Verify update
		retrieved, _ := adapter.GetByHash(ctx, "test-hash")
		assert.Equal(t, "Updated", retrieved.Name)
	})

	t.Run("nil apiKeyInfo returns validation error", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		err := adapter.Update(ctx, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "api_key_info")
		assert.True(t, errors.Is(err, ErrInvalidInput))
	})

	t.Run("update non-existent key returns not found", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		apiKeyInfo := &APIKeyInfo{
			APIKeyHash: "nonexistent",
			UserID:     "test-user",
			OrgID:      "test-org",
		}

		err := adapter.Update(ctx, apiKeyInfo)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrAPIKeyNotFound))
	})

	t.Run("repository update error", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		// Create key first
		apiKeyInfo := &APIKeyInfo{
			APIKeyHash: "test-hash",
			UserID:     "test-user",
			OrgID:      "test-org",
		}
		adapter.Create(ctx, apiKeyInfo)

		// Inject error
		mockRepo.updateError = errors.New("update failure")

		// Try to update
		apiKeyInfo.Name = "New Name"
		err := adapter.Update(ctx, apiKeyInfo)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "repository_update")
	})

	t.Run("updates all fields", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		// Create
		apiKeyInfo := &APIKeyInfo{
			APIKeyHash: "test-hash",
			UserID:     "user1",
			OrgID:      "org1",
			Name:       "Name1",
			Email:      "email1@example.com",
		}
		adapter.Create(ctx, apiKeyInfo)

		// Update all fields
		apiKeyInfo.Name = "Name2"
		apiKeyInfo.Email = "email2@example.com"
		apiKeyInfo.Roles = []string{"admin"}
		err := adapter.Update(ctx, apiKeyInfo)
		assert.NoError(t, err)

		// Verify all updates
		retrieved, _ := adapter.GetByHash(ctx, "test-hash")
		assert.Equal(t, "Name2", retrieved.Name)
		assert.Equal(t, "email2@example.com", retrieved.Email)
		assert.Equal(t, []string{"admin"}, retrieved.Roles)
	})

	t.Run("exists check error propagates", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		mockRepo.readError = errors.New("read failure for exists check")
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		apiKeyInfo := &APIKeyInfo{
			APIKeyHash: "test-hash",
			UserID:     "test-user",
			OrgID:      "test-org",
		}

		err := adapter.Update(ctx, apiKeyInfo)
		assert.Error(t, err)
		// Error comes from Exists() call
	})

	t.Run("preserves user_id and org_id during update", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		// Create with specific IDs
		apiKeyInfo := &APIKeyInfo{
			APIKeyHash: "test-hash",
			UserID:     "original-user",
			OrgID:      "original-org",
			Name:       "Original",
		}
		adapter.Create(ctx, apiKeyInfo)

		// Update name only
		apiKeyInfo.Name = "Updated"
		adapter.Update(ctx, apiKeyInfo)

		// Verify IDs unchanged
		retrieved, _ := adapter.GetByHash(ctx, "test-hash")
		assert.Equal(t, "original-user", retrieved.UserID)
		assert.Equal(t, "original-org", retrieved.OrgID)
		assert.Equal(t, "Updated", retrieved.Name)
	})
}

// =============================================================================
// Delete Tests (6 tests)
// =============================================================================

func TestDataRepositoryAdapter_Delete(t *testing.T) {
	t.Run("successful deletion", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		// Create key
		apiKeyInfo := &APIKeyInfo{
			APIKeyHash: "test-hash",
			UserID:     "test-user",
			OrgID:      "test-org",
		}
		adapter.Create(ctx, apiKeyInfo)

		// Delete it
		err := adapter.Delete(ctx, "test-hash")
		assert.NoError(t, err)

		// Verify deleted
		exists, _ := adapter.Exists(ctx, "test-hash")
		assert.False(t, exists)
	})

	t.Run("empty hash returns validation error", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		err := adapter.Delete(ctx, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "hash")
		assert.True(t, errors.Is(err, ErrInvalidInput))
	})

	t.Run("delete non-existent key returns not found", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		err := adapter.Delete(ctx, "nonexistent")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrAPIKeyNotFound))
	})

	t.Run("repository delete error", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		// Create key
		apiKeyInfo := &APIKeyInfo{
			APIKeyHash: "test-hash",
			UserID:     "test-user",
			OrgID:      "test-org",
		}
		adapter.Create(ctx, apiKeyInfo)

		// Inject error
		mockRepo.deleteError = errors.New("delete failure")

		// Try to delete
		err := adapter.Delete(ctx, "test-hash")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "repository_delete")
	})

	t.Run("double delete returns not found", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		// Create and delete
		apiKeyInfo := &APIKeyInfo{
			APIKeyHash: "test-hash",
			UserID:     "test-user",
			OrgID:      "test-org",
		}
		adapter.Create(ctx, apiKeyInfo)
		adapter.Delete(ctx, "test-hash")

		// Try to delete again
		err := adapter.Delete(ctx, "test-hash")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrAPIKeyNotFound))
	})

	t.Run("exists check error propagates", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		mockRepo.readError = errors.New("read failure for exists check")
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		err := adapter.Delete(ctx, "test-hash")
		assert.Error(t, err)
		// Error comes from Exists() call
	})
}

// =============================================================================
// Search Tests (8 tests)
// =============================================================================

func TestDataRepositoryAdapter_Search(t *testing.T) {
	t.Run("successful search returns all keys", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		// Create multiple keys
		for i := 0; i < 5; i++ {
			adapter.Create(ctx, &APIKeyInfo{
				APIKeyHash: string(rune('a' + i)),
				UserID:     "user",
				OrgID:      "org",
			})
		}

		// Search
		results, total, err := adapter.Search(ctx, nil, 0, 10)
		assert.NoError(t, err)
		assert.Equal(t, 5, total)
		assert.Len(t, results, 5)
	})

	t.Run("pagination - first page", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		// Create 10 keys
		for i := 0; i < 10; i++ {
			adapter.Create(ctx, &APIKeyInfo{
				APIKeyHash: string(rune('a' + i)),
				UserID:     "user",
				OrgID:      "org",
			})
		}

		// Get first 5
		results, total, err := adapter.Search(ctx, nil, 0, 5)
		assert.NoError(t, err)
		assert.Equal(t, 10, total)
		assert.Len(t, results, 5)
	})

	t.Run("pagination - second page", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		// Create 10 keys
		for i := 0; i < 10; i++ {
			adapter.Create(ctx, &APIKeyInfo{
				APIKeyHash: string(rune('a' + i)),
				UserID:     "user",
				OrgID:      "org",
			})
		}

		// Get second 5
		results, total, err := adapter.Search(ctx, nil, 5, 5)
		assert.NoError(t, err)
		assert.Equal(t, 10, total)
		assert.Len(t, results, 5)
	})

	t.Run("pagination - offset beyond results", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		// Create 5 keys
		for i := 0; i < 5; i++ {
			adapter.Create(ctx, &APIKeyInfo{
				APIKeyHash: string(rune('a' + i)),
				UserID:     "user",
				OrgID:      "org",
			})
		}

		// Offset beyond results
		results, total, err := adapter.Search(ctx, nil, 10, 5)
		assert.NoError(t, err)
		assert.Equal(t, 5, total)
		assert.Empty(t, results)
	})

	t.Run("empty repository returns empty results", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		results, total, err := adapter.Search(ctx, nil, 0, 10)
		assert.NoError(t, err)
		assert.Equal(t, 0, total)
		assert.Empty(t, results)
	})

	t.Run("repository list error", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		mockRepo.listError = errors.New("list failure")
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		results, total, err := adapter.Search(ctx, nil, 0, 10)
		assert.Error(t, err)
		assert.Zero(t, total)
		assert.Nil(t, results)
		assert.Contains(t, err.Error(), "repository_search")
	})

	t.Run("skips malformed JSON entities", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		// Create valid key
		adapter.Create(ctx, &APIKeyInfo{
			APIKeyHash: "valid",
			UserID:     "user",
			OrgID:      "org",
		})

		// Inject malformed data
		mockRepo.data["invalid"] = "not-valid-json"

		// Search should skip malformed entry
		results, total, err := adapter.Search(ctx, nil, 0, 10)
		assert.NoError(t, err)
		assert.Equal(t, 1, total) // Only counts valid entries
		assert.Len(t, results, 1)
	})

	t.Run("query parameter is ignored (not implemented)", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		// Create keys
		for i := 0; i < 3; i++ {
			adapter.Create(ctx, &APIKeyInfo{
				APIKeyHash: string(rune('a' + i)),
				UserID:     "user",
				OrgID:      "org",
			})
		}

		// Query is ignored, returns all
		query := map[string]interface{}{"user_id": "specific"}
		results, total, err := adapter.Search(ctx, query, 0, 10)
		assert.NoError(t, err)
		assert.Equal(t, 3, total) // Returns all, not filtered
		assert.Len(t, results, 3)
	})
}

// =============================================================================
// Exists Tests (5 tests)
// =============================================================================

func TestDataRepositoryAdapter_Exists(t *testing.T) {
	t.Run("returns true for existing key", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		// Create key
		adapter.Create(ctx, &APIKeyInfo{
			APIKeyHash: "test-hash",
			UserID:     "test-user",
			OrgID:      "test-org",
		})

		// Check exists
		exists, err := adapter.Exists(ctx, "test-hash")
		assert.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("returns false for non-existent key", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		exists, err := adapter.Exists(ctx, "nonexistent")
		assert.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("empty hash returns validation error", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		exists, err := adapter.Exists(ctx, "")
		assert.Error(t, err)
		assert.False(t, exists)
		assert.Contains(t, err.Error(), "hash")
		assert.True(t, errors.Is(err, ErrInvalidInput))
	})

	t.Run("repository read error", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		mockRepo.readError = errors.New("read failure")
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		exists, err := adapter.Exists(ctx, "test-hash")
		assert.Error(t, err)
		assert.False(t, exists)
		assert.Contains(t, err.Error(), "repository_exists")
	})

	t.Run("returns false after deletion", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		// Create and delete
		adapter.Create(ctx, &APIKeyInfo{
			APIKeyHash: "test-hash",
			UserID:     "test-user",
			OrgID:      "test-org",
		})
		adapter.Delete(ctx, "test-hash")

		// Check exists
		exists, err := adapter.Exists(ctx, "test-hash")
		assert.NoError(t, err)
		assert.False(t, exists)
	})
}

// =============================================================================
// Integration Tests (2 tests)
// =============================================================================

func TestDataRepositoryAdapter_Integration(t *testing.T) {
	t.Run("full CRUD lifecycle", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		// Create
		apiKeyInfo := &APIKeyInfo{
			APIKeyHash: "lifecycle-hash",
			UserID:     "user",
			OrgID:      "org",
			Name:       "Original",
		}
		err := adapter.Create(ctx, apiKeyInfo)
		require.NoError(t, err)

		// Read
		retrieved, err := adapter.GetByHash(ctx, "lifecycle-hash")
		require.NoError(t, err)
		assert.Equal(t, "Original", retrieved.Name)

		// Update
		apiKeyInfo.Name = "Updated"
		err = adapter.Update(ctx, apiKeyInfo)
		require.NoError(t, err)

		// Read again
		retrieved, err = adapter.GetByHash(ctx, "lifecycle-hash")
		require.NoError(t, err)
		assert.Equal(t, "Updated", retrieved.Name)

		// Delete
		err = adapter.Delete(ctx, "lifecycle-hash")
		require.NoError(t, err)

		// Verify deleted
		exists, err := adapter.Exists(ctx, "lifecycle-hash")
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("search pagination consistency", func(t *testing.T) {
		mockRepo := newMockDataRepository()
		adapter, _ := NewDataRepositoryAdapter(mockRepo)
		ctx := context.Background()

		// Create 15 keys
		for i := 0; i < 15; i++ {
			adapter.Create(ctx, &APIKeyInfo{
				APIKeyHash: string(rune('a' + i)),
				UserID:     "user",
				OrgID:      "org",
			})
		}

		// Get first page
		page1, total1, _ := adapter.Search(ctx, nil, 0, 5)
		assert.Equal(t, 15, total1)
		assert.Len(t, page1, 5)

		// Get second page
		page2, total2, _ := adapter.Search(ctx, nil, 5, 5)
		assert.Equal(t, 15, total2)
		assert.Len(t, page2, 5)

		// Get third page
		page3, total3, _ := adapter.Search(ctx, nil, 10, 5)
		assert.Equal(t, 15, total3)
		assert.Len(t, page3, 5)

		// Verify no duplicates between pages
		hashes := make(map[string]bool)
		for _, key := range append(append(page1, page2...), page3...) {
			assert.False(t, hashes[key.APIKeyHash], "Found duplicate hash across pages")
			hashes[key.APIKeyHash] = true
		}
	})
}
