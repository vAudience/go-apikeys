package apikeys

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func setupHandlerTest() (*HandlerCore, *APIKeyManager, *mockRepository) {
	mockRepo := newMockRepository()
	logger, _ := zap.NewDevelopment()

	// Create service directly with mock repository (implements APIKeyRepository interface)
	service, err := NewAPIKeyService(mockRepo, logger, DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH, 0, 0)
	if err != nil {
		panic(err) // OK in test setup
	}

	// Create minimal manager for testing
	manager := &APIKeyManager{
		logger:  logger.Named(CLASS_APIKEY_MANAGER),
		service: service,
	}

	core := NewHandlerCore(manager)
	return core, manager, mockRepo
}

func createSystemAdminKey(t *testing.T, manager *APIKeyManager) *APIKeyInfo {
	ctx := context.Background()
	adminKey := &APIKeyInfo{
		UserID: "admin-user",
		OrgID:  "system",
		Metadata: map[string]any{
			METADATA_KEY_SYSTEM_ADMIN: true,
		},
	}
	created, err := manager.CreateAPIKey(ctx, adminKey)
	require.NoError(t, err)
	return created
}

func TestNewSuccessResult(t *testing.T) {
	t.Run("creates success result with data", func(t *testing.T) {
		data := map[string]string{"key": "value"}
		result := NewSuccessResult(http.StatusOK, data)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		assert.Equal(t, data, result.Data)
		assert.Empty(t, result.Error)
	})

	t.Run("creates success result with nil data", func(t *testing.T) {
		result := NewSuccessResult(http.StatusNoContent, nil)
		assert.Equal(t, http.StatusNoContent, result.StatusCode)
		assert.Nil(t, result.Data)
		assert.Empty(t, result.Error)
	})
}

func TestNewErrorResult(t *testing.T) {
	t.Run("creates error result", func(t *testing.T) {
		result := NewErrorResult(http.StatusBadRequest, "test error")
		assert.Equal(t, http.StatusBadRequest, result.StatusCode)
		assert.Equal(t, "test error", result.Error)
		assert.Nil(t, result.Data)
	})
}

func TestHandlerCore_HandleCreateAPIKey(t *testing.T) {
	core, manager, _ := setupHandlerTest()
	ctx := context.Background()

	t.Run("successful creation", func(t *testing.T) {
		adminKey := createSystemAdminKey(t, manager)

		newKey := &APIKeyInfo{
			UserID: "new-user",
			OrgID:  "new-org",
			Email:  "new@example.com",
		}
		body, _ := json.Marshal(newKey)

		result := core.HandleCreateAPIKey(ctx, body, adminKey)
		assert.Equal(t, http.StatusCreated, result.StatusCode)
		assert.Empty(t, result.Error)
		assert.NotNil(t, result.Data)

		// Verify returned data
		returnedKey, ok := result.Data.(*APIKeyInfo)
		assert.True(t, ok)
		assert.Equal(t, "new-user", returnedKey.UserID)
		assert.NotEmpty(t, returnedKey.APIKey) // API key should be included
	})

	t.Run("unauthorized - nil apiKeyInfo", func(t *testing.T) {
		body := []byte(`{"user_id":"test","org_id":"test"}`)
		result := core.HandleCreateAPIKey(ctx, body, nil)
		assert.Equal(t, http.StatusUnauthorized, result.StatusCode)
		assert.Equal(t, ERROR_UNAUTHORIZED_NOT_SYSTEM_ADMIN, result.Error)
	})

	t.Run("unauthorized - not system admin", func(t *testing.T) {
		regularUser := &APIKeyInfo{
			UserID: "regular-user",
			OrgID:  "regular-org",
		}
		body := []byte(`{"user_id":"test","org_id":"test"}`)
		result := core.HandleCreateAPIKey(ctx, body, regularUser)
		assert.Equal(t, http.StatusUnauthorized, result.StatusCode)
		assert.Equal(t, ERROR_UNAUTHORIZED_NOT_SYSTEM_ADMIN, result.Error)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		adminKey := createSystemAdminKey(t, manager)
		body := []byte(`{invalid json}`)
		result := core.HandleCreateAPIKey(ctx, body, adminKey)
		assert.Equal(t, http.StatusBadRequest, result.StatusCode)
		assert.Equal(t, ERROR_INVALID_JSON, result.Error)
	})

	t.Run("validation error - missing user_id", func(t *testing.T) {
		adminKey := createSystemAdminKey(t, manager)
		body := []byte(`{"org_id":"test"}`)
		result := core.HandleCreateAPIKey(ctx, body, adminKey)
		assert.Equal(t, http.StatusBadRequest, result.StatusCode)
		assert.Contains(t, result.Error, "user_id")
	})
}

func TestHandlerCore_HandleSearchAPIKeys(t *testing.T) {
	core, manager, _ := setupHandlerTest()
	ctx := context.Background()

	t.Run("successful search", func(t *testing.T) {
		adminKey := createSystemAdminKey(t, manager)

		// Create some test keys
		for i := 0; i < 3; i++ {
			_, err := manager.CreateAPIKey(ctx, &APIKeyInfo{
				UserID: "user-" + string(rune(i)),
				OrgID:  "org",
			})
			require.NoError(t, err)
		}

		result := core.HandleSearchAPIKeys(ctx, adminKey)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		assert.Empty(t, result.Error)
		assert.NotNil(t, result.Data)

		response, ok := result.Data.(map[string]interface{})
		assert.True(t, ok, "Expected response to be a map")
		assert.Contains(t, response, "items")
		assert.Contains(t, response, "total")

		keys, ok := response["items"].([]*APIKeyInfo)
		assert.True(t, ok)
		assert.NotEmpty(t, keys)
	})

	t.Run("unauthorized - nil apiKeyInfo", func(t *testing.T) {
		result := core.HandleSearchAPIKeys(ctx, nil)
		assert.Equal(t, http.StatusUnauthorized, result.StatusCode)
		assert.Equal(t, ERROR_UNAUTHORIZED_NOT_SYSTEM_ADMIN, result.Error)
	})

	t.Run("unauthorized - not system admin", func(t *testing.T) {
		regularUser := &APIKeyInfo{
			UserID: "regular-user",
			OrgID:  "regular-org",
		}
		result := core.HandleSearchAPIKeys(ctx, regularUser)
		assert.Equal(t, http.StatusUnauthorized, result.StatusCode)
		assert.Equal(t, ERROR_UNAUTHORIZED_NOT_SYSTEM_ADMIN, result.Error)
	})
}

func TestHandlerCore_HandleGetAPIKey(t *testing.T) {
	core, manager, _ := setupHandlerTest()
	ctx := context.Background()

	t.Run("successful get by hash", func(t *testing.T) {
		adminKey := createSystemAdminKey(t, manager)
		testKey, err := manager.CreateAPIKey(ctx, &APIKeyInfo{
			UserID: "test-user",
			OrgID:  "test-org",
		})
		require.NoError(t, err)

		result := core.HandleGetAPIKey(ctx, testKey.APIKeyHash, adminKey)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		assert.Empty(t, result.Error)
		assert.NotNil(t, result.Data)

		retrievedKey, ok := result.Data.(*APIKeyInfo)
		assert.True(t, ok)
		assert.Equal(t, "test-user", retrievedKey.UserID)
	})

	t.Run("unauthorized - not system admin", func(t *testing.T) {
		regularUser := &APIKeyInfo{
			UserID: "regular-user",
			OrgID:  "regular-org",
		}
		result := core.HandleGetAPIKey(ctx, "some-hash", regularUser)
		assert.Equal(t, http.StatusUnauthorized, result.StatusCode)
		assert.Equal(t, ERROR_UNAUTHORIZED_NOT_SYSTEM_ADMIN, result.Error)
	})

	t.Run("missing keyOrHash", func(t *testing.T) {
		adminKey := createSystemAdminKey(t, manager)
		result := core.HandleGetAPIKey(ctx, "", adminKey)
		assert.Equal(t, http.StatusBadRequest, result.StatusCode)
		assert.Equal(t, ERROR_MISSING_APIKEY_OR_HASH, result.Error)
	})

	t.Run("not found", func(t *testing.T) {
		adminKey := createSystemAdminKey(t, manager)
		result := core.HandleGetAPIKey(ctx, "nonexistent-hash", adminKey)
		assert.Equal(t, http.StatusNotFound, result.StatusCode)
		assert.Contains(t, result.Error, "not found")
	})
}

func TestHandlerCore_HandleUpdateAPIKey(t *testing.T) {
	core, manager, _ := setupHandlerTest()
	ctx := context.Background()

	t.Run("successful update", func(t *testing.T) {
		adminKey := createSystemAdminKey(t, manager)
		testKey, err := manager.CreateAPIKey(ctx, &APIKeyInfo{
			UserID: "test-user",
			OrgID:  "test-org",
			Name:   "Original Name",
		})
		require.NoError(t, err)

		updateData := map[string]interface{}{
			"user_id": "test-user",
			"org_id":  "test-org",
			"name":    "Updated Name",
		}
		body, _ := json.Marshal(updateData)

		result := core.HandleUpdateAPIKey(ctx, testKey.APIKeyHash, body, adminKey)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		assert.Empty(t, result.Error)
		assert.NotNil(t, result.Data)

		updatedKey, ok := result.Data.(*APIKeyInfo)
		assert.True(t, ok)
		assert.Equal(t, "Updated Name", updatedKey.Name)
	})

	t.Run("unauthorized - not system admin", func(t *testing.T) {
		regularUser := &APIKeyInfo{
			UserID: "regular-user",
			OrgID:  "regular-org",
		}
		body := []byte(`{"name":"Updated"}`)
		result := core.HandleUpdateAPIKey(ctx, "some-hash", body, regularUser)
		assert.Equal(t, http.StatusUnauthorized, result.StatusCode)
		assert.Equal(t, ERROR_UNAUTHORIZED_NOT_SYSTEM_ADMIN, result.Error)
	})

	t.Run("missing keyOrHash", func(t *testing.T) {
		adminKey := createSystemAdminKey(t, manager)
		body := []byte(`{"name":"Updated"}`)
		result := core.HandleUpdateAPIKey(ctx, "", body, adminKey)
		assert.Equal(t, http.StatusBadRequest, result.StatusCode)
		assert.Equal(t, ERROR_MISSING_APIKEY_HASH, result.Error)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		adminKey := createSystemAdminKey(t, manager)
		body := []byte(`{invalid json}`)
		result := core.HandleUpdateAPIKey(ctx, "some-hash", body, adminKey)
		assert.Equal(t, http.StatusBadRequest, result.StatusCode)
		assert.Equal(t, ERROR_INVALID_JSON, result.Error)
	})
}

func TestHandlerCore_HandleDeleteAPIKey(t *testing.T) {
	core, manager, _ := setupHandlerTest()
	ctx := context.Background()

	t.Run("successful delete", func(t *testing.T) {
		adminKey := createSystemAdminKey(t, manager)
		testKey, err := manager.CreateAPIKey(ctx, &APIKeyInfo{
			UserID: "test-user",
			OrgID:  "test-org",
		})
		require.NoError(t, err)

		result := core.HandleDeleteAPIKey(ctx, testKey.APIKeyHash, adminKey)
		assert.Equal(t, http.StatusNoContent, result.StatusCode)
		assert.Empty(t, result.Error)
		assert.Nil(t, result.Data)

		// Verify it's deleted
		exists, _ := manager.service.Exists(ctx, testKey.APIKeyHash)
		assert.False(t, exists)
	})

	t.Run("unauthorized - not system admin", func(t *testing.T) {
		regularUser := &APIKeyInfo{
			UserID: "regular-user",
			OrgID:  "regular-org",
		}
		result := core.HandleDeleteAPIKey(ctx, "some-hash", regularUser)
		assert.Equal(t, http.StatusUnauthorized, result.StatusCode)
		assert.Equal(t, ERROR_UNAUTHORIZED_NOT_SYSTEM_ADMIN, result.Error)
	})

	t.Run("missing keyOrHash", func(t *testing.T) {
		adminKey := createSystemAdminKey(t, manager)
		result := core.HandleDeleteAPIKey(ctx, "", adminKey)
		assert.Equal(t, http.StatusBadRequest, result.StatusCode)
		assert.Equal(t, ERROR_MISSING_APIKEY_OR_HASH, result.Error)
	})

	t.Run("not found", func(t *testing.T) {
		adminKey := createSystemAdminKey(t, manager)
		result := core.HandleDeleteAPIKey(ctx, "nonexistent-hash", adminKey)
		assert.Equal(t, http.StatusNotFound, result.StatusCode)
		assert.Contains(t, result.Error, "not found")
	})
}

func TestHandlerCore_HandleIsSystemAdmin(t *testing.T) {
	core, manager, _ := setupHandlerTest()

	t.Run("is system admin", func(t *testing.T) {
		adminKey := createSystemAdminKey(t, manager)
		result := core.HandleIsSystemAdmin(adminKey)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		assert.Empty(t, result.Error)

		data, ok := result.Data.(map[string]bool)
		assert.True(t, ok)
		assert.True(t, data[RESPONSE_KEY_IS_SYSTEM_ADMIN])
	})

	t.Run("not system admin", func(t *testing.T) {
		regularUser := &APIKeyInfo{
			UserID: "regular-user",
			OrgID:  "regular-org",
		}
		result := core.HandleIsSystemAdmin(regularUser)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		assert.Empty(t, result.Error)

		data, ok := result.Data.(map[string]bool)
		assert.True(t, ok)
		assert.False(t, data[RESPONSE_KEY_IS_SYSTEM_ADMIN])
	})

	t.Run("nil apiKeyInfo", func(t *testing.T) {
		result := core.HandleIsSystemAdmin(nil)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		assert.Empty(t, result.Error)

		data, ok := result.Data.(map[string]bool)
		assert.True(t, ok)
		assert.False(t, data[RESPONSE_KEY_IS_SYSTEM_ADMIN])
	})
}
