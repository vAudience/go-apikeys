package apikeys

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Helper Functions
// =============================================================================

func setupTestCRUDHandlers(t *testing.T) (*StandardHandlers, *APIKeyService, *mockRepository) {
	repo := newMockRepository()
	logger := NewTestLogger(t)

	service, err := NewAPIKeyService(repo, logger, DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH, 0, 0)
	require.NoError(t, err)

	// Create a minimal manager for testing
	// We'll bypass the full New() constructor to avoid repository interface issues
	manager := &APIKeyManager{
		service:   service,
		logger:    logger,
		framework: &GorillaMuxFramework{}, // Use GorillaMux framework for stdlib context handling
	}

	handlers := NewStandardHandlers(manager)
	return handlers, service, repo
}

// =============================================================================
// stdlibResponse Helper Tests (5 tests)
// =============================================================================

func TestStdlibResponse(t *testing.T) {
	t.Run("success with data", func(t *testing.T) {
		w := httptest.NewRecorder()
		result := &HandlerResult{
			StatusCode: 200,
			Data:       map[string]string{"message": "success"},
		}

		stdlibResponse(w, result)

		assert.Equal(t, 200, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

		var response map[string]string
		json.NewDecoder(w.Body).Decode(&response)
		assert.Equal(t, "success", response["message"])
	})

	t.Run("error response", func(t *testing.T) {
		w := httptest.NewRecorder()
		result := &HandlerResult{
			StatusCode: 400,
			Error:      "bad request",
		}

		stdlibResponse(w, result)

		assert.Equal(t, 400, w.Code)

		var response map[string]string
		json.NewDecoder(w.Body).Decode(&response)
		assert.Equal(t, "bad request", response[RESPONSE_KEY_ERROR])
	})

	t.Run("204 no content", func(t *testing.T) {
		w := httptest.NewRecorder()
		result := &HandlerResult{
			StatusCode: 204,
		}

		stdlibResponse(w, result)

		assert.Equal(t, 204, w.Code)
		assert.Empty(t, w.Body.String())
	})

	t.Run("nil data", func(t *testing.T) {
		w := httptest.NewRecorder()
		result := &HandlerResult{
			StatusCode: 200,
			Data:       nil,
		}

		stdlibResponse(w, result)

		assert.Equal(t, 200, w.Code)
	})

	t.Run("complex data structure", func(t *testing.T) {
		w := httptest.NewRecorder()
		result := &HandlerResult{
			StatusCode: 200,
			Data: &APIKeyInfo{
				UserID: "test-user",
				OrgID:  "test-org",
				Email:  "test@example.com",
			},
		}

		stdlibResponse(w, result)

		assert.Equal(t, 200, w.Code)

		var response APIKeyInfo
		json.NewDecoder(w.Body).Decode(&response)
		assert.Equal(t, "test-user", response.UserID)
	})
}

// =============================================================================
// NewStandardHandlers Tests (1 test)
// =============================================================================

func TestNewStandardHandlers(t *testing.T) {
	t.Run("creates handlers correctly", func(t *testing.T) {
		handlers, _, _ := setupTestCRUDHandlers(t)

		assert.NotNil(t, handlers)
		assert.NotNil(t, handlers.manager)
		assert.NotNil(t, handlers.core)
	})
}

// =============================================================================
// CreateAPIKey Handler Tests (5 tests)
// =============================================================================

func TestCreateAPIKey_Handler(t *testing.T) {
	t.Run("successful creation", func(t *testing.T) {
		handlers, service, _ := setupTestCRUDHandlers(t)

		// Create admin key for authentication
		adminKey := CreateTestAdminAPIKey(t, service)

		// Create request
		reqBody := NewTestAPIKeyInfo()
		bodyBytes, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/apikeys", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")

		// Set API key in context (simulate middleware)
		ctx := context.WithValue(req.Context(), contextKeyAPIKeyInfo, adminKey)
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handlers.CreateAPIKey(w, req)

		assert.Equal(t, 201, w.Code)

		var response APIKeyInfo
		json.NewDecoder(w.Body).Decode(&response)
		assert.NotEmpty(t, response.APIKey)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		handlers, service, _ := setupTestCRUDHandlers(t)
		adminKey := CreateTestAdminAPIKey(t, service)

		req := httptest.NewRequest("POST", "/apikeys", strings.NewReader("invalid json"))
		ctx := context.WithValue(req.Context(), contextKeyAPIKeyInfo, adminKey)
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handlers.CreateAPIKey(w, req)

		assert.Equal(t, 400, w.Code)
	})

	t.Run("missing required fields", func(t *testing.T) {
		handlers, service, _ := setupTestCRUDHandlers(t)
		adminKey := CreateTestAdminAPIKey(t, service)

		// Missing org_id
		reqBody := map[string]string{"user_id": "test"}
		bodyBytes, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/apikeys", bytes.NewReader(bodyBytes))
		ctx := context.WithValue(req.Context(), contextKeyAPIKeyInfo, adminKey)
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handlers.CreateAPIKey(w, req)

		assert.Equal(t, 400, w.Code)
	})

	t.Run("unauthorized - not system admin", func(t *testing.T) {
		handlers, service, _ := setupTestCRUDHandlers(t)
		regularKey := CreateTestAPIKey(t, service)

		reqBody := NewTestAPIKeyInfo()
		bodyBytes, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/apikeys", bytes.NewReader(bodyBytes))
		ctx := context.WithValue(req.Context(), contextKeyAPIKeyInfo, regularKey)
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handlers.CreateAPIKey(w, req)

		assert.Equal(t, 401, w.Code)
	})

	t.Run("body read error", func(t *testing.T) {
		handlers, service, _ := setupTestCRUDHandlers(t)
		adminKey := CreateTestAdminAPIKey(t, service)

		// Use a reader that returns an error
		errorReader := &errorReader{}
		req := httptest.NewRequest("POST", "/apikeys", errorReader)
		ctx := context.WithValue(req.Context(), contextKeyAPIKeyInfo, adminKey)
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handlers.CreateAPIKey(w, req)

		assert.Equal(t, 400, w.Code)
	})
}

// errorReader is a helper that always returns an error on Read
type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}

// =============================================================================
// SearchAPIKeys Handler Tests (3 tests)
// =============================================================================

func TestSearchAPIKeys_Handler(t *testing.T) {
	t.Run("successful search", func(t *testing.T) {
		handlers, service, _ := setupTestCRUDHandlers(t)
		adminKey := CreateTestAdminAPIKey(t, service)

		// Create some test keys
		CreateTestAPIKey(t, service)
		CreateTestAPIKey(t, service)

		req := httptest.NewRequest("GET", "/apikeys/search", nil)
		ctx := context.WithValue(req.Context(), contextKeyAPIKeyInfo, adminKey)
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handlers.SearchAPIKeys(w, req)

		assert.Equal(t, 200, w.Code)

		var response struct {
			Items []*APIKeyInfo `json:"items"`
			Total int           `json:"total"`
		}
		json.NewDecoder(w.Body).Decode(&response)
		assert.GreaterOrEqual(t, response.Total, 2)
	})

	t.Run("unauthorized", func(t *testing.T) {
		handlers, _, _ := setupTestCRUDHandlers(t)

		req := httptest.NewRequest("GET", "/apikeys/search", nil)

		w := httptest.NewRecorder()
		handlers.SearchAPIKeys(w, req)

		assert.Equal(t, 401, w.Code)
	})

	t.Run("empty results", func(t *testing.T) {
		handlers, service, _ := setupTestCRUDHandlers(t)
		adminKey := CreateTestAdminAPIKey(t, service)

		req := httptest.NewRequest("GET", "/apikeys/search", nil)
		ctx := context.WithValue(req.Context(), contextKeyAPIKeyInfo, adminKey)
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handlers.SearchAPIKeys(w, req)

		assert.Equal(t, 200, w.Code)
	})
}

// =============================================================================
// GetAPIKey Handler Tests (4 tests)
// =============================================================================

func TestGetAPIKey_Handler(t *testing.T) {
	t.Run("key found", func(t *testing.T) {
		handlers, service, _ := setupTestCRUDHandlers(t)
		adminKey := CreateTestAdminAPIKey(t, service)
		created := CreateTestAPIKey(t, service)

		req := httptest.NewRequest("GET", "/apikeys/"+created.APIKeyHash, nil)
		req.SetPathValue("key_or_hash", created.APIKeyHash)
		ctx := context.WithValue(req.Context(), contextKeyAPIKeyInfo, adminKey)
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handlers.GetAPIKey(w, req)

		assert.Equal(t, 200, w.Code)

		var response APIKeyInfo
		json.NewDecoder(w.Body).Decode(&response)
		assert.Equal(t, created.UserID, response.UserID)
	})

	t.Run("key not found", func(t *testing.T) {
		handlers, service, _ := setupTestCRUDHandlers(t)
		adminKey := CreateTestAdminAPIKey(t, service)

		req := httptest.NewRequest("GET", "/apikeys/nonexistent", nil)
		req.SetPathValue("key_or_hash", "nonexistent")
		ctx := context.WithValue(req.Context(), contextKeyAPIKeyInfo, adminKey)
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handlers.GetAPIKey(w, req)

		assert.Equal(t, 404, w.Code)
	})

	t.Run("missing key parameter", func(t *testing.T) {
		handlers, service, _ := setupTestCRUDHandlers(t)
		adminKey := CreateTestAdminAPIKey(t, service)

		req := httptest.NewRequest("GET", "/apikeys/", nil)
		// Don't set PathValue - simulate missing param
		ctx := context.WithValue(req.Context(), contextKeyAPIKeyInfo, adminKey)
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handlers.GetAPIKey(w, req)

		assert.Equal(t, 400, w.Code)
	})

	t.Run("unauthorized", func(t *testing.T) {
		handlers, _, _ := setupTestCRUDHandlers(t)

		req := httptest.NewRequest("GET", "/apikeys/somehash", nil)
		req.SetPathValue("key_or_hash", "somehash")

		w := httptest.NewRecorder()
		handlers.GetAPIKey(w, req)

		assert.Equal(t, 401, w.Code)
	})
}

// =============================================================================
// UpdateAPIKey Handler Tests (5 tests)
// =============================================================================

func TestUpdateAPIKey_Handler(t *testing.T) {
	t.Run("successful update", func(t *testing.T) {
		handlers, service, _ := setupTestCRUDHandlers(t)
		adminKey := CreateTestAdminAPIKey(t, service)
		created := CreateTestAPIKey(t, service)

		updateInfo := &APIKeyInfo{
			APIKeyHash: created.APIKeyHash,
			UserID:     created.UserID,
			OrgID:      created.OrgID,
			Name:       "Updated Name",
		}
		bodyBytes, _ := json.Marshal(updateInfo)

		req := httptest.NewRequest("PUT", "/apikeys/"+created.APIKeyHash, bytes.NewReader(bodyBytes))
		req.SetPathValue("key_or_hash", created.APIKeyHash)
		ctx := context.WithValue(req.Context(), contextKeyAPIKeyInfo, adminKey)
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handlers.UpdateAPIKey(w, req)

		assert.Equal(t, 200, w.Code)

		var response APIKeyInfo
		json.NewDecoder(w.Body).Decode(&response)
		assert.Equal(t, "Updated Name", response.Name)
	})

	t.Run("key not found", func(t *testing.T) {
		handlers, service, _ := setupTestCRUDHandlers(t)
		adminKey := CreateTestAdminAPIKey(t, service)

		updateInfo := &APIKeyInfo{
			APIKeyHash: "nonexistent",
			UserID:     "test",
			OrgID:      "test",
		}
		bodyBytes, _ := json.Marshal(updateInfo)

		req := httptest.NewRequest("PUT", "/apikeys/nonexistent", bytes.NewReader(bodyBytes))
		req.SetPathValue("key_or_hash", "nonexistent")
		ctx := context.WithValue(req.Context(), contextKeyAPIKeyInfo, adminKey)
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handlers.UpdateAPIKey(w, req)

		assert.Equal(t, 404, w.Code)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		handlers, service, _ := setupTestCRUDHandlers(t)
		adminKey := CreateTestAdminAPIKey(t, service)

		req := httptest.NewRequest("PUT", "/apikeys/test", strings.NewReader("invalid json"))
		req.SetPathValue("key_or_hash", "test")
		ctx := context.WithValue(req.Context(), contextKeyAPIKeyInfo, adminKey)
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handlers.UpdateAPIKey(w, req)

		assert.Equal(t, 400, w.Code)
	})

	t.Run("body read error", func(t *testing.T) {
		handlers, service, _ := setupTestCRUDHandlers(t)
		adminKey := CreateTestAdminAPIKey(t, service)

		req := httptest.NewRequest("PUT", "/apikeys/test", &errorReader{})
		req.SetPathValue("key_or_hash", "test")
		ctx := context.WithValue(req.Context(), contextKeyAPIKeyInfo, adminKey)
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handlers.UpdateAPIKey(w, req)

		assert.Equal(t, 400, w.Code)
	})

	t.Run("unauthorized", func(t *testing.T) {
		handlers, service, _ := setupTestCRUDHandlers(t)
		created := CreateTestAPIKey(t, service)

		updateInfo := &APIKeyInfo{
			APIKeyHash: created.APIKeyHash,
			UserID:     created.UserID,
			OrgID:      created.OrgID,
		}
		bodyBytes, _ := json.Marshal(updateInfo)

		req := httptest.NewRequest("PUT", "/apikeys/"+created.APIKeyHash, bytes.NewReader(bodyBytes))
		req.SetPathValue("key_or_hash", created.APIKeyHash)
		// Don't set context - unauthorized

		w := httptest.NewRecorder()
		handlers.UpdateAPIKey(w, req)

		assert.Equal(t, 401, w.Code)
	})
}

// =============================================================================
// DeleteAPIKey Handler Tests (3 tests)
// =============================================================================

func TestDeleteAPIKey_Handler(t *testing.T) {
	t.Run("successful deletion", func(t *testing.T) {
		handlers, service, _ := setupTestCRUDHandlers(t)
		adminKey := CreateTestAdminAPIKey(t, service)
		created := CreateTestAPIKey(t, service)

		req := httptest.NewRequest("DELETE", "/apikeys/"+created.APIKeyHash, nil)
		req.SetPathValue("key_or_hash", created.APIKeyHash)
		ctx := context.WithValue(req.Context(), contextKeyAPIKeyInfo, adminKey)
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handlers.DeleteAPIKey(w, req)

		assert.Equal(t, 204, w.Code)
	})

	t.Run("key not found", func(t *testing.T) {
		handlers, service, _ := setupTestCRUDHandlers(t)
		adminKey := CreateTestAdminAPIKey(t, service)

		req := httptest.NewRequest("DELETE", "/apikeys/nonexistent", nil)
		req.SetPathValue("key_or_hash", "nonexistent")
		ctx := context.WithValue(req.Context(), contextKeyAPIKeyInfo, adminKey)
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handlers.DeleteAPIKey(w, req)

		assert.Equal(t, 404, w.Code)
	})

	t.Run("unauthorized", func(t *testing.T) {
		handlers, _, _ := setupTestCRUDHandlers(t)

		req := httptest.NewRequest("DELETE", "/apikeys/test", nil)
		req.SetPathValue("key_or_hash", "test")
		// No context - unauthorized

		w := httptest.NewRecorder()
		handlers.DeleteAPIKey(w, req)

		assert.Equal(t, 401, w.Code)
	})
}

// =============================================================================
// IsSystemAdmin Handler Tests (2 tests)
// =============================================================================

func TestIsSystemAdmin_Handler(t *testing.T) {
	t.Run("admin key returns true", func(t *testing.T) {
		handlers, service, _ := setupTestCRUDHandlers(t)
		adminKey := CreateTestAdminAPIKey(t, service)

		req := httptest.NewRequest("GET", "/apikeys/issystemadmin", nil)
		ctx := context.WithValue(req.Context(), contextKeyAPIKeyInfo, adminKey)
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handlers.IsSystemAdmin(w, req)

		assert.Equal(t, 200, w.Code)

		var response map[string]interface{}
		json.NewDecoder(w.Body).Decode(&response)
		assert.True(t, response[RESPONSE_KEY_IS_SYSTEM_ADMIN].(bool))
	})

	t.Run("regular key returns false", func(t *testing.T) {
		handlers, service, _ := setupTestCRUDHandlers(t)
		regularKey := CreateTestAPIKey(t, service)

		req := httptest.NewRequest("GET", "/apikeys/issystemadmin", nil)
		ctx := context.WithValue(req.Context(), contextKeyAPIKeyInfo, regularKey)
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handlers.IsSystemAdmin(w, req)

		assert.Equal(t, 200, w.Code)

		var response map[string]interface{}
		json.NewDecoder(w.Body).Decode(&response)
		assert.False(t, response[RESPONSE_KEY_IS_SYSTEM_ADMIN].(bool))
	})
}

// =============================================================================
// RegisterCRUDRoutes Tests (3 tests)
// =============================================================================

func TestRegisterCRUDRoutes(t *testing.T) {
	t.Run("registers routes on http.ServeMux", func(t *testing.T) {
		handlers, _, _ := setupTestCRUDHandlers(t)
		mux := http.NewServeMux()

		RegisterCRUDRoutes(mux, handlers.manager)

		// Test that routes respond (not 404)
		routes := []struct {
			method string
			path   string
		}{
			{"POST", "/apikeys"},
			{"GET", "/apikeys/search"},
			{"GET", "/apikeys/issystemadmin"},
			{"GET", "/apikeys/test123"},
		}

		for _, route := range routes {
			req := httptest.NewRequest(route.method, route.path, nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			// Should not be 404 (routes are registered, even if auth fails)
			assert.NotEqual(t, 404, w.Code, "Route %s %s should be registered", route.method, route.path)
		}
	})

	t.Run("handles unsupported router type", func(t *testing.T) {
		handlers, _, _ := setupTestCRUDHandlers(t)

		// Should not panic
		assert.NotPanics(t, func() {
			RegisterCRUDRoutes("unsupported-router", handlers.manager)
		})
	})

	t.Run("supports method routing on dynamic route", func(t *testing.T) {
		handlers, service, _ := setupTestCRUDHandlers(t)
		created := CreateTestAPIKey(t, service)

		mux := http.NewServeMux()
		RegisterCRUDRoutes(mux, handlers.manager)

		// Test GET
		req := httptest.NewRequest("GET", "/apikeys/"+created.APIKeyHash, nil)
		ctx := context.WithValue(req.Context(), contextKeyAPIKeyInfo, created)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.NotEqual(t, 405, w.Code) // Not Method Not Allowed

		// Test PUT
		updateBody := map[string]string{"user_id": created.UserID, "org_id": created.OrgID}
		bodyBytes, _ := json.Marshal(updateBody)
		req = httptest.NewRequest("PUT", "/apikeys/"+created.APIKeyHash, bytes.NewReader(bodyBytes))
		ctx = context.WithValue(req.Context(), contextKeyAPIKeyInfo, created)
		req = req.WithContext(ctx)
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.NotEqual(t, 405, w.Code)

		// Test DELETE
		req = httptest.NewRequest("DELETE", "/apikeys/"+created.APIKeyHash, nil)
		ctx = context.WithValue(req.Context(), contextKeyAPIKeyInfo, created)
		req = req.WithContext(ctx)
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.NotEqual(t, 405, w.Code)

		// Test unsupported method
		req = httptest.NewRequest("PATCH", "/apikeys/"+created.APIKeyHash, nil)
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, 405, w.Code) // Should be Method Not Allowed
	})
}
