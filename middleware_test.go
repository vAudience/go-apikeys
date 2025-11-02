package apikeys

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func setupMiddlewareTest() (*APIKeyManager, *mockRepository, *APIKeyInfo) {
	mockRepo := newMockRepository()
	logger, _ := zap.NewDevelopment()
	service, err := NewAPIKeyService(mockRepo, logger, DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH, 0, 0)
	if err != nil {
		panic(err) // OK in test setup
	}

	config := &Config{
		Logger:       logger,
		ApiKeyPrefix: DEFAULT_APIKEY_PREFIX,
		ApiKeyLength: DEFAULT_APIKEY_LENGTH,
		HeaderKey:    "X-API-Key",
	}
	config.ApplyDefaults()

	manager := &APIKeyManager{
		config:  config,
		logger:  logger.Named(CLASS_APIKEY_MANAGER),
		service: service,
	}

	// Create a test API key
	apiKeyInfo := &APIKeyInfo{
		UserID: "test-user",
		OrgID:  "test-org",
	}
	created, _ := service.CreateAPIKey(context.Background(), apiKeyInfo)

	return manager, mockRepo, created
}

// Test standard middleware (stdlib/Gorilla Mux)
func TestStandardMiddleware(t *testing.T) {
	t.Run("valid API key passes through", func(t *testing.T) {
		manager, _, testKey := setupMiddlewareTest()

		middleware := manager.standardMiddleware()

		handlerCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			// Verify API key info is in context (using typed key for stdlib)
			value := r.Context().Value(contextKeyAPIKeyInfo)
			assert.NotNil(t, value)
			apiKeyInfo, ok := value.(*APIKeyInfo)
			assert.True(t, ok)
			assert.Equal(t, "test-user", apiKeyInfo.UserID)
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-API-Key", testKey.APIKey)
		w := httptest.NewRecorder()

		handler := middleware(nextHandler)
		handler.ServeHTTP(w, req)

		assert.True(t, handlerCalled)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("invalid API key returns 401", func(t *testing.T) {
		manager, _, _ := setupMiddlewareTest()

		middleware := manager.standardMiddleware()

		handlerCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-API-Key", "invalid-key")
		w := httptest.NewRecorder()

		handler := middleware(nextHandler)
		handler.ServeHTTP(w, req)

		assert.False(t, handlerCalled)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		body, _ := io.ReadAll(w.Body)
		// Generic error message to prevent information leakage
		assert.Contains(t, string(body), "unauthorized")
	})

	t.Run("missing API key returns 401", func(t *testing.T) {
		manager, _, _ := setupMiddlewareTest()

		middleware := manager.standardMiddleware()

		handlerCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		// No API key header
		w := httptest.NewRecorder()

		handler := middleware(nextHandler)
		handler.ServeHTTP(w, req)

		assert.False(t, handlerCalled)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("ignored route pattern skips authentication", func(t *testing.T) {
		manager, _, _ := setupMiddlewareTest()
		manager.config.IgnoreApiKeyForRoutePatterns = []string{"/health", "/metrics"}

		middleware := manager.standardMiddleware()

		handlerCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			// Should NOT have API key info in context (using typed key for stdlib)
			value := r.Context().Value(contextKeyAPIKeyInfo)
			assert.Nil(t, value)
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		// No API key header
		w := httptest.NewRecorder()

		handler := middleware(nextHandler)
		handler.ServeHTTP(w, req)

		assert.True(t, handlerCalled)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// Test Fiber middleware
func TestFiberMiddleware(t *testing.T) {
	t.Run("valid API key passes through", func(t *testing.T) {
		manager, _, testKey := setupMiddlewareTest()

		app := fiber.New()
		app.Use(manager.fiberMiddleware())

		handlerCalled := false
		app.Get("/test", func(c *fiber.Ctx) error {
			handlerCalled = true
			// Verify API key info is in context
			value := c.Locals(LOCALS_KEY_APIKEYS)
			assert.NotNil(t, value)
			apiKeyInfo, ok := value.(*APIKeyInfo)
			assert.True(t, ok)
			assert.Equal(t, "test-user", apiKeyInfo.UserID)
			return c.SendStatus(fiber.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-API-Key", testKey.APIKey)

		resp, err := app.Test(req)
		require.NoError(t, err)

		assert.True(t, handlerCalled)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("invalid API key returns 401", func(t *testing.T) {
		manager, _, _ := setupMiddlewareTest()

		app := fiber.New()
		app.Use(manager.fiberMiddleware())

		handlerCalled := false
		app.Get("/test", func(c *fiber.Ctx) error {
			handlerCalled = true
			return c.SendStatus(fiber.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-API-Key", "invalid-key")

		resp, err := app.Test(req)
		require.NoError(t, err)

		assert.False(t, handlerCalled)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("missing API key returns 401", func(t *testing.T) {
		manager, _, _ := setupMiddlewareTest()

		app := fiber.New()
		app.Use(manager.fiberMiddleware())

		handlerCalled := false
		app.Get("/test", func(c *fiber.Ctx) error {
			handlerCalled = true
			return c.SendStatus(fiber.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		// No API key header

		resp, err := app.Test(req)
		require.NoError(t, err)

		assert.False(t, handlerCalled)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("ignored route pattern skips authentication", func(t *testing.T) {
		manager, _, _ := setupMiddlewareTest()
		manager.config.IgnoreApiKeyForRoutePatterns = []string{"/health", "/metrics"}

		app := fiber.New()
		app.Use(manager.fiberMiddleware())

		handlerCalled := false
		app.Get("/health", func(c *fiber.Ctx) error {
			handlerCalled = true
			// Should NOT have API key info in context
			value := c.Locals(LOCALS_KEY_APIKEYS)
			assert.Nil(t, value)
			return c.SendStatus(fiber.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		// No API key header

		resp, err := app.Test(req)
		require.NoError(t, err)

		assert.True(t, handlerCalled)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})
}

// Test Middleware() function
func TestAPIKeyManager_Middleware(t *testing.T) {
	t.Run("returns fiber middleware for Fiber framework", func(t *testing.T) {
		manager, _, _ := setupMiddlewareTest()
		// Explicitly set Fiber framework
		manager.framework = &FiberFramework{}

		middleware := manager.Middleware()
		_, ok := middleware.(fiber.Handler)
		assert.True(t, ok, "Should return fiber.Handler for Fiber framework")
	})

	t.Run("returns standard middleware for non-Fiber framework (default)", func(t *testing.T) {
		manager, _, _ := setupMiddlewareTest()
		// Leave framework as nil or any non-Fiber framework
		manager.framework = nil

		middleware := manager.Middleware()
		_, ok := middleware.(func(http.Handler) http.Handler)
		assert.True(t, ok, "Should return func(http.Handler) http.Handler for non-Fiber framework")
	})
}
