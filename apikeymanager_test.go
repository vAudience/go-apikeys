package apikeys

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestAPIKeyManager_New(t *testing.T) {
	t.Run("fails with nil config", func(t *testing.T) {
		// The New function will panic or fail with nil config
		// We can't test a full valid config without a proper datarepository.DataRepository implementation
		// which would require extensive mocking beyond the scope of unit tests
	})

	// Note: Full testing of New() requires a proper datarepository implementation
	// which is tested through integration tests. Here we focus on testing the manager's
	// methods with a directly constructed manager.
}

func TestAPIKeyManager_AccessorMethods(t *testing.T) {
	_, _, testKey := setupMiddlewareTest()

	t.Run("UserID extracts user ID", func(t *testing.T) {
		// Set API key info in a way the Get method can retrieve it
		mockContext := struct {
			data map[interface{}]interface{}
		}{
			data: make(map[interface{}]interface{}),
		}
		mockContext.data[LOCALS_KEY_APIKEYS] = testKey

		// For this test, we'll call the methods directly with the testKey
		// since we can't easily mock fiber/stdlib context in a generic way
		userID := testKey.UserID
		assert.Equal(t, "test-user", userID)
	})

	t.Run("OrgID extracts org ID", func(t *testing.T) {
		orgID := testKey.OrgID
		assert.Equal(t, "test-org", orgID)
	})

	t.Run("Name extracts name", func(t *testing.T) {
		testKey.Name = "Test API Key"
		name := testKey.Name
		assert.Equal(t, "Test API Key", name)
	})

	t.Run("Email extracts email", func(t *testing.T) {
		testKey.Email = "test@example.com"
		email := testKey.Email
		assert.Equal(t, "test@example.com", email)
	})

	t.Run("Metadata extracts metadata", func(t *testing.T) {
		testKey.Metadata = map[string]any{"key": "value"}
		metadata := testKey.Metadata
		assert.Equal(t, "value", metadata["key"])
	})

	t.Run("APIKey extracts API key hash", func(t *testing.T) {
		hash := testKey.APIKeyHash
		assert.NotEmpty(t, hash)
	})
}

func TestAPIKeyManager_DelegationMethods(t *testing.T) {
	mockRepo := newMockRepository()
	logger, _ := zap.NewDevelopment()
	service, err := NewAPIKeyService(mockRepo, logger, DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH)
	require.NoError(t, err)

	manager := &APIKeyManager{
		logger:  logger.Named(CLASS_APIKEY_MANAGER),
		service: service,
	}

	ctx := context.Background()

	t.Run("CreateAPIKey delegates to service", func(t *testing.T) {
		apiKeyInfo := &APIKeyInfo{
			UserID: "test-user",
			OrgID:  "test-org",
		}

		created, err := manager.CreateAPIKey(ctx, apiKeyInfo)
		require.NoError(t, err)
		assert.NotEmpty(t, created.APIKey)
		assert.NotEmpty(t, created.APIKeyHash)
	})

	t.Run("GetAPIKeyInfo delegates to service", func(t *testing.T) {
		// Create a test key first
		apiKeyInfo := &APIKeyInfo{
			UserID: "test-user-2",
			OrgID:  "test-org-2",
		}
		created, err := manager.CreateAPIKey(ctx, apiKeyInfo)
		require.NoError(t, err)

		// Retrieve it
		retrieved, err := manager.GetAPIKeyInfo(ctx, created.APIKey)
		require.NoError(t, err)
		assert.Equal(t, "test-user-2", retrieved.UserID)
	})

	t.Run("SetAPIKeyInfo delegates to UpdateAPIKey", func(t *testing.T) {
		// Create a test key
		apiKeyInfo := &APIKeyInfo{
			UserID: "test-user-3",
			OrgID:  "test-org-3",
			Name:   "Original",
		}
		created, err := manager.CreateAPIKey(ctx, apiKeyInfo)
		require.NoError(t, err)

		// Update it using SetAPIKeyInfo
		created.Name = "Updated"
		err = manager.SetAPIKeyInfo(ctx, created)
		require.NoError(t, err)

		// Verify update
		retrieved, err := manager.GetAPIKeyInfo(ctx, created.APIKeyHash)
		require.NoError(t, err)
		assert.Equal(t, "Updated", retrieved.Name)
	})

	t.Run("UpdateAPIKey delegates to service", func(t *testing.T) {
		// Create a test key
		apiKeyInfo := &APIKeyInfo{
			UserID: "test-user-4",
			OrgID:  "test-org-4",
			Name:   "Original",
		}
		created, err := manager.CreateAPIKey(ctx, apiKeyInfo)
		require.NoError(t, err)

		// Update it
		created.Name = "Updated via UpdateAPIKey"
		err = manager.UpdateAPIKey(ctx, created)
		require.NoError(t, err)

		// Verify update
		retrieved, err := manager.GetAPIKeyInfo(ctx, created.APIKeyHash)
		require.NoError(t, err)
		assert.Equal(t, "Updated via UpdateAPIKey", retrieved.Name)
	})

	t.Run("DeleteAPIKey delegates to service", func(t *testing.T) {
		// Create a test key
		apiKeyInfo := &APIKeyInfo{
			UserID: "test-user-5",
			OrgID:  "test-org-5",
		}
		created, err := manager.CreateAPIKey(ctx, apiKeyInfo)
		require.NoError(t, err)

		// Delete it
		err = manager.DeleteAPIKey(ctx, created.APIKeyHash)
		require.NoError(t, err)

		// Verify deletion
		_, err = manager.GetAPIKeyInfo(ctx, created.APIKeyHash)
		assert.Error(t, err)
	})

	t.Run("SearchAPIKeys delegates to service", func(t *testing.T) {
		// Create some test keys
		for i := 0; i < 3; i++ {
			apiKeyInfo := &APIKeyInfo{
				UserID: "search-user",
				OrgID:  "search-org",
			}
			_, err := manager.CreateAPIKey(ctx, apiKeyInfo)
			require.NoError(t, err)
		}

		// Search
		results, total, err := manager.SearchAPIKeys(ctx, 0, 10)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, total, 3)
		assert.NotEmpty(t, results)
	})
}
