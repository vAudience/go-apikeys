package apikeys

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// mockRepository is a simple in-memory repository for testing
type mockRepository struct {
	data map[string]*APIKeyInfo
}

func newMockRepository() *mockRepository {
	return &mockRepository{
		data: make(map[string]*APIKeyInfo),
	}
}

func (m *mockRepository) Create(ctx context.Context, apiKeyInfo *APIKeyInfo) error {
	if apiKeyInfo.APIKeyHash == "" {
		return NewValidationError("api_key_hash", "cannot be empty")
	}
	if _, exists := m.data[apiKeyInfo.APIKeyHash]; exists {
		return NewValidationError("api_key", "already exists")
	}
	m.data[apiKeyInfo.APIKeyHash] = apiKeyInfo
	return nil
}

func (m *mockRepository) GetByHash(ctx context.Context, hash string) (*APIKeyInfo, error) {
	if info, exists := m.data[hash]; exists {
		return info, nil
	}
	return nil, ErrAPIKeyNotFound
}

func (m *mockRepository) Update(ctx context.Context, apiKeyInfo *APIKeyInfo) error {
	if _, exists := m.data[apiKeyInfo.APIKeyHash]; !exists {
		return ErrAPIKeyNotFound
	}
	m.data[apiKeyInfo.APIKeyHash] = apiKeyInfo
	return nil
}

func (m *mockRepository) Delete(ctx context.Context, hash string) error {
	if _, exists := m.data[hash]; !exists {
		return ErrAPIKeyNotFound
	}
	delete(m.data, hash)
	return nil
}

func (m *mockRepository) Search(ctx context.Context, query map[string]interface{}, offset, limit int) ([]*APIKeyInfo, int, error) {
	var results []*APIKeyInfo
	for _, info := range m.data {
		results = append(results, info)
	}

	total := len(results)

	// Apply pagination
	start := offset
	end := offset + limit
	if start > len(results) {
		start = len(results)
	}
	if end > len(results) {
		end = len(results)
	}

	if start < end {
		results = results[start:end]
	} else {
		results = []*APIKeyInfo{}
	}

	return results, total, nil
}

func (m *mockRepository) Exists(ctx context.Context, hash string) (bool, error) {
	_, exists := m.data[hash]
	return exists, nil
}

func setupTestService() (*APIKeyService, *mockRepository) {
	repo := newMockRepository()
	logger, _ := zap.NewDevelopment()
	service, err := NewAPIKeyService(repo, logger, DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH)
	if err != nil {
		panic(err) // OK in test setup
	}
	return service, repo
}

func TestAPIKeyService_CreateAPIKey(t *testing.T) {
	service, _ := setupTestService()
	ctx := context.Background()

	t.Run("successful creation with generated key", func(t *testing.T) {
		apiKeyInfo := &APIKeyInfo{
			UserID: "test-user",
			OrgID:  "test-org",
			Email:  "test@example.com",
			Name:   "Test Key",
		}

		created, err := service.CreateAPIKey(ctx, apiKeyInfo)
		require.NoError(t, err)
		assert.NotEmpty(t, created.APIKey, "API key should be generated")
		assert.NotEmpty(t, created.APIKeyHash, "Hash should be generated")
		assert.NotEmpty(t, created.APIKeyHint, "Hint should be generated")
		assert.Equal(t, "test-user", created.UserID)
	})

	t.Run("successful creation with provided key", func(t *testing.T) {
		customKey, _ := GenerateAPIKey(DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH)
		apiKeyInfo := &APIKeyInfo{
			APIKey: customKey,
			UserID: "test-user-2",
			OrgID:  "test-org",
		}

		created, err := service.CreateAPIKey(ctx, apiKeyInfo)
		require.NoError(t, err)
		assert.Equal(t, customKey, created.APIKey)
	})

	t.Run("validation error - missing user_id", func(t *testing.T) {
		apiKeyInfo := &APIKeyInfo{
			OrgID: "test-org",
		}

		_, err := service.CreateAPIKey(ctx, apiKeyInfo)
		assert.Error(t, err)
	})

	t.Run("validation error - missing org_id", func(t *testing.T) {
		apiKeyInfo := &APIKeyInfo{
			UserID: "test-user",
		}

		_, err := service.CreateAPIKey(ctx, apiKeyInfo)
		assert.Error(t, err)
	})
}

func TestAPIKeyService_GetAPIKeyInfo(t *testing.T) {
	service, repo := setupTestService()
	ctx := context.Background()

	// Create a test key
	apiKeyInfo := &APIKeyInfo{
		UserID: "test-user",
		OrgID:  "test-org",
	}
	created, err := service.CreateAPIKey(ctx, apiKeyInfo)
	require.NoError(t, err)

	t.Run("get by plain API key", func(t *testing.T) {
		retrieved, err := service.GetAPIKeyInfo(ctx, created.APIKey)
		require.NoError(t, err)
		assert.Equal(t, created.UserID, retrieved.UserID)
		assert.Equal(t, created.APIKeyHash, retrieved.APIKeyHash)
	})

	t.Run("get by hash", func(t *testing.T) {
		retrieved, err := service.GetAPIKeyInfo(ctx, created.APIKeyHash)
		require.NoError(t, err)
		assert.Equal(t, created.UserID, retrieved.UserID)
	})

	t.Run("not found", func(t *testing.T) {
		_, err := service.GetAPIKeyInfo(ctx, "nonexistent")
		assert.Error(t, err)
		assert.Equal(t, ErrAPIKeyNotFound, err)
	})

	t.Run("empty key", func(t *testing.T) {
		_, err := service.GetAPIKeyInfo(ctx, "")
		assert.Error(t, err)
	})

	// Clean up
	_ = repo.Delete(ctx, created.APIKeyHash)
}

func TestAPIKeyService_UpdateAPIKey(t *testing.T) {
	service, repo := setupTestService()
	ctx := context.Background()

	// Create a test key
	apiKeyInfo := &APIKeyInfo{
		UserID: "test-user",
		OrgID:  "test-org",
		Name:   "Original Name",
	}
	created, err := service.CreateAPIKey(ctx, apiKeyInfo)
	require.NoError(t, err)

	t.Run("successful update", func(t *testing.T) {
		updated := &APIKeyInfo{
			APIKeyHash: created.APIKeyHash,
			UserID:     "test-user",
			OrgID:      "test-org",
			Name:       "Updated Name",
			Email:      "updated@example.com",
		}

		err := service.UpdateAPIKey(ctx, updated)
		require.NoError(t, err)

		retrieved, err := service.GetAPIKeyInfo(ctx, created.APIKeyHash)
		require.NoError(t, err)
		assert.Equal(t, "Updated Name", retrieved.Name)
		assert.Equal(t, "updated@example.com", retrieved.Email)
	})

	t.Run("not found", func(t *testing.T) {
		updated := &APIKeyInfo{
			APIKeyHash: "nonexistent",
			UserID:     "test-user",
			OrgID:      "test-org",
		}

		err := service.UpdateAPIKey(ctx, updated)
		assert.Error(t, err)
		assert.Equal(t, ErrAPIKeyNotFound, err)
	})

	// Clean up
	_ = repo.Delete(ctx, created.APIKeyHash)
}

func TestAPIKeyService_DeleteAPIKey(t *testing.T) {
	service, _ := setupTestService()
	ctx := context.Background()

	// Create a test key
	apiKeyInfo := &APIKeyInfo{
		UserID: "test-user",
		OrgID:  "test-org",
	}
	created, err := service.CreateAPIKey(ctx, apiKeyInfo)
	require.NoError(t, err)

	t.Run("successful delete by hash", func(t *testing.T) {
		err := service.DeleteAPIKey(ctx, created.APIKeyHash)
		require.NoError(t, err)

		// Verify it's deleted
		_, err = service.GetAPIKeyInfo(ctx, created.APIKeyHash)
		assert.Error(t, err)
		assert.Equal(t, ErrAPIKeyNotFound, err)
	})

	t.Run("delete nonexistent key", func(t *testing.T) {
		err := service.DeleteAPIKey(ctx, "nonexistent")
		assert.Error(t, err)
		assert.Equal(t, ErrAPIKeyNotFound, err)
	})
}

func TestAPIKeyService_SearchAPIKeys(t *testing.T) {
	service, repo := setupTestService()
	ctx := context.Background()

	// Create multiple test keys
	for i := 0; i < 5; i++ {
		apiKeyInfo := &APIKeyInfo{
			UserID: "test-user",
			OrgID:  "test-org",
		}
		_, err := service.CreateAPIKey(ctx, apiKeyInfo)
		require.NoError(t, err)
	}

	t.Run("search all", func(t *testing.T) {
		results, total, err := service.SearchAPIKeys(ctx, nil, 0, 10)
		require.NoError(t, err)
		assert.Equal(t, 5, total)
		assert.Len(t, results, 5)
	})

	t.Run("search with pagination", func(t *testing.T) {
		results, total, err := service.SearchAPIKeys(ctx, nil, 0, 2)
		require.NoError(t, err)
		assert.Equal(t, 5, total)
		assert.Len(t, results, 2)
	})

	t.Run("search with offset", func(t *testing.T) {
		results, total, err := service.SearchAPIKeys(ctx, nil, 3, 10)
		require.NoError(t, err)
		assert.Equal(t, 5, total)
		assert.Len(t, results, 2)
	})

	// Clean up
	for hash := range repo.data {
		_ = repo.Delete(ctx, hash)
	}
}

func TestAPIKeyService_ValidateAPIKey(t *testing.T) {
	service, repo := setupTestService()
	ctx := context.Background()

	// Create a test key
	apiKeyInfo := &APIKeyInfo{
		UserID: "test-user",
		OrgID:  "test-org",
	}
	created, err := service.CreateAPIKey(ctx, apiKeyInfo)
	require.NoError(t, err)

	t.Run("valid key", func(t *testing.T) {
		validated, err := service.ValidateAPIKey(ctx, created.APIKey)
		require.NoError(t, err)
		assert.Equal(t, created.UserID, validated.UserID)
	})

	t.Run("invalid key format", func(t *testing.T) {
		_, err := service.ValidateAPIKey(ctx, "invalid-key")
		assert.Error(t, err)
	})

	t.Run("nonexistent key", func(t *testing.T) {
		fakeKey, _ := GenerateAPIKey(DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH)
		_, err := service.ValidateAPIKey(ctx, fakeKey)
		assert.Error(t, err)
		assert.Equal(t, ErrAPIKeyNotFound, err)
	})

	// Clean up
	_ = repo.Delete(ctx, created.APIKeyHash)
}

func TestAPIKeyService_IsSystemAdmin(t *testing.T) {
	service, _ := setupTestService()

	t.Run("is system admin", func(t *testing.T) {
		apiKeyInfo := &APIKeyInfo{
			UserID: "admin",
			OrgID:  "system",
			Metadata: map[string]any{
				METADATA_KEY_SYSTEM_ADMIN: true,
			},
		}

		isAdmin := service.IsSystemAdmin(apiKeyInfo)
		assert.True(t, isAdmin)
	})

	t.Run("not system admin - no metadata", func(t *testing.T) {
		apiKeyInfo := &APIKeyInfo{
			UserID: "user",
			OrgID:  "org",
		}

		isAdmin := service.IsSystemAdmin(apiKeyInfo)
		assert.False(t, isAdmin)
	})

	t.Run("not system admin - metadata false", func(t *testing.T) {
		apiKeyInfo := &APIKeyInfo{
			UserID: "user",
			OrgID:  "org",
			Metadata: map[string]any{
				METADATA_KEY_SYSTEM_ADMIN: false,
			},
		}

		isAdmin := service.IsSystemAdmin(apiKeyInfo)
		assert.False(t, isAdmin)
	})

	t.Run("nil apiKeyInfo", func(t *testing.T) {
		isAdmin := service.IsSystemAdmin(nil)
		assert.False(t, isAdmin)
	})
}

func TestAPIKeyService_Exists(t *testing.T) {
	service, repo := setupTestService()
	ctx := context.Background()

	// Create a test key
	apiKeyInfo := &APIKeyInfo{
		UserID: "test-user",
		OrgID:  "test-org",
	}
	created, err := service.CreateAPIKey(ctx, apiKeyInfo)
	require.NoError(t, err)

	t.Run("exists by hash", func(t *testing.T) {
		exists, err := service.Exists(ctx, created.APIKeyHash)
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("exists by plain key", func(t *testing.T) {
		exists, err := service.Exists(ctx, created.APIKey)
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("does not exist", func(t *testing.T) {
		exists, err := service.Exists(ctx, "nonexistent")
		require.NoError(t, err)
		assert.False(t, exists)
	})

	// Clean up
	_ = repo.Delete(ctx, created.APIKeyHash)
}
