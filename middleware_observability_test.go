package apikeys

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func setupObservabilityTest() (*APIKeyManager, *APIKeyInfo, *mockMetricsProvider, *mockAuditProvider) {
	mockRepo := newMockRepository()
	logger, _ := zap.NewDevelopment()
	service, err := NewAPIKeyService(mockRepo, logger, DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH, 0, 0)
	if err != nil {
		panic(err)
	}

	// Create observability with mock providers
	metrics := newMockMetricsProvider()
	audit := newMockAuditProvider()
	obs := NewObservability(metrics, audit, nil)
	service.SetObservability(obs)

	config := &Config{
		Logger:       logger,
		ApiKeyPrefix: DEFAULT_APIKEY_PREFIX,
		ApiKeyLength: DEFAULT_APIKEY_LENGTH,
		HeaderKey:    "X-API-Key",
	}
	config.ApplyDefaults()

	manager := &APIKeyManager{
		config:        config,
		logger:        logger.Named(CLASS_APIKEY_MANAGER),
		service:       service,
		observability: obs,
	}

	// Create a test API key
	apiKeyInfo := &APIKeyInfo{
		UserID: "test-user",
		OrgID:  "test-org",
		Name:   "Test Key",
	}
	created, _ := service.CreateAPIKey(context.Background(), apiKeyInfo)

	return manager, created, metrics, audit
}

func TestMiddleware_Observability_SuccessfulAuth(t *testing.T) {
	manager, testKey, metrics, audit := setupObservabilityTest()
	middleware := manager.standardMiddleware()

	t.Run("stdlib middleware records successful auth metrics", func(t *testing.T) {
		metrics.Reset()
		audit.Reset()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-API-Key", testKey.APIKey)
		rr := httptest.NewRecorder()

		middleware(handler).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		// Verify metrics were recorded
		assert.Equal(t, 1, metrics.GetAuthAttemptCount(), "should record 1 auth attempt")
		assert.Equal(t, 1, metrics.GetAuthSuccessCount(), "should record 1 success")
		assert.Equal(t, 0, metrics.GetAuthFailureCount(), "should record 0 failures")

		// Verify audit event was logged
		assert.Equal(t, 1, audit.GetAuthEventCount(), "should log 1 auth event")
		lastEvent := audit.GetLastAuthEvent()
		require.NotNil(t, lastEvent)
		assert.Equal(t, EventTypeAuthSuccess, lastEvent.EventType)
		assert.Equal(t, OutcomeSuccess, lastEvent.Outcome)
		assert.Equal(t, "test-user", lastEvent.Actor.UserID)
		assert.Equal(t, "test-org", lastEvent.Actor.OrgID)
	})
}

func TestMiddleware_Observability_FailedAuth(t *testing.T) {
	manager, _, metrics, audit := setupObservabilityTest()
	middleware := manager.standardMiddleware()

	t.Run("stdlib middleware records missing key error", func(t *testing.T) {
		metrics.Reset()
		audit.Reset()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("handler should not be called")
		})

		req := httptest.NewRequest("GET", "/test", nil)
		// No Authorization header
		rr := httptest.NewRecorder()

		middleware(handler).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)

		// Verify metrics were recorded
		assert.Equal(t, 1, metrics.GetAuthAttemptCount(), "should record 1 auth attempt")
		assert.Equal(t, 0, metrics.GetAuthSuccessCount(), "should record 0 successes")
		assert.Equal(t, 1, metrics.GetAuthFailureCount(), "should record 1 failure")

		// Verify audit event was logged
		assert.Equal(t, 1, audit.GetAuthEventCount(), "should log 1 auth event")
		lastEvent := audit.GetLastAuthEvent()
		require.NotNil(t, lastEvent)
		assert.Equal(t, EventTypeAuthFailure, lastEvent.EventType)
		assert.Equal(t, OutcomeFailure, lastEvent.Outcome)
		assert.False(t, lastEvent.KeyProvided, "no key was provided")
	})

	t.Run("stdlib middleware records invalid key error", func(t *testing.T) {
		metrics.Reset()
		audit.Reset()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("handler should not be called")
		})

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-API-Key", "gak_invalid_key_not_found_1234567890")
		rr := httptest.NewRecorder()

		middleware(handler).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)

		// Verify metrics were recorded
		assert.Equal(t, 1, metrics.GetAuthAttemptCount(), "should record 1 auth attempt")
		assert.Equal(t, 1, metrics.GetAuthFailureCount(), "should record 1 failure")

		// Verify audit event was logged
		assert.Equal(t, 1, audit.GetAuthEventCount(), "should log 1 auth event")
		lastEvent := audit.GetLastAuthEvent()
		require.NotNil(t, lastEvent)
		assert.Equal(t, EventTypeAuthFailure, lastEvent.EventType)
		assert.Equal(t, OutcomeFailure, lastEvent.Outcome)
		assert.True(t, lastEvent.KeyProvided, "key was provided")
		assert.False(t, lastEvent.KeyValid, "but key was not valid")
	})

	t.Run("stdlib middleware records malformed key error", func(t *testing.T) {
		metrics.Reset()
		audit.Reset()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("handler should not be called")
		})

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-API-Key", "invalid-format")
		rr := httptest.NewRecorder()

		middleware(handler).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)

		// Verify metrics were recorded
		assert.Equal(t, 1, metrics.GetAuthAttemptCount(), "should record 1 auth attempt")
		assert.Equal(t, 1, metrics.GetAuthFailureCount(), "should record 1 failure")

		// Verify audit event was logged
		assert.Equal(t, 1, audit.GetAuthEventCount(), "should log 1 auth event")
		lastEvent := audit.GetLastAuthEvent()
		require.NotNil(t, lastEvent)
		assert.True(t, lastEvent.KeyProvided, "key was provided")
		assert.False(t, lastEvent.KeyValid, "but format was invalid")
	})
}

func TestMiddleware_Observability_MetricsLabels(t *testing.T) {
	manager, testKey, metrics, _ := setupObservabilityTest()
	middleware := manager.standardMiddleware()

	t.Run("metrics include org_id label", func(t *testing.T) {
		metrics.Reset()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/test/endpoint", nil)
		req.Header.Set("X-API-Key", testKey.APIKey)
		rr := httptest.NewRecorder()

		middleware(handler).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		// Verify metrics were recorded with labels
		assert.Equal(t, 1, metrics.GetAuthAttemptCount())

		// Check that the mock captured labels (org_id should be present)
		attempts := metrics.authAttempts
		require.Len(t, attempts, 1)
		assert.Equal(t, "test-org", attempts[0].labels["org_id"])
		assert.Equal(t, "/test/endpoint", attempts[0].labels["endpoint"])
	})
}

func TestMiddleware_Observability_AuditEventDetails(t *testing.T) {
	manager, testKey, _, audit := setupObservabilityTest()
	middleware := manager.standardMiddleware()

	t.Run("audit event contains complete details", func(t *testing.T) {
		audit.Reset()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("POST", "/api/v1/data", nil)
		req.Header.Set("X-API-Key", testKey.APIKey)
		req.Header.Set("User-Agent", "TestClient/1.0")
		req.RemoteAddr = "192.168.1.100:12345"
		rr := httptest.NewRecorder()

		middleware(handler).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		// Verify audit event details
		assert.Equal(t, 1, audit.GetAuthEventCount())
		event := audit.GetLastAuthEvent()
		require.NotNil(t, event)

		// Verify actor info
		assert.Equal(t, "test-user", event.Actor.UserID)
		assert.Equal(t, "test-org", event.Actor.OrgID)
		assert.Equal(t, testKey.APIKeyHash, event.Actor.APIKeyHash)
		assert.Contains(t, event.Actor.IPAddress, "192.168.1.100")
		assert.Equal(t, "TestClient/1.0", event.Actor.UserAgent)

		// Verify resource info
		assert.Equal(t, "endpoint", event.Resource.Type)
		assert.Equal(t, "/api/v1/data", event.Resource.ID)

		// Verify auth attempt details
		assert.Equal(t, "api_key", event.Method)
		assert.True(t, event.KeyProvided)
		assert.True(t, event.KeyValid)
		assert.True(t, event.KeyFound)
		assert.Equal(t, "/api/v1/data", event.Endpoint)
		assert.Equal(t, "POST", event.HTTPMethod)
		assert.GreaterOrEqual(t, event.LatencyMS, int64(0))

		// Verify event ID and timestamp
		assert.NotEmpty(t, event.EventID)
		assert.False(t, event.Timestamp.IsZero())
	})
}

func TestMiddleware_Observability_ConcurrentRequests(t *testing.T) {
	manager, testKey, metrics, audit := setupObservabilityTest()
	middleware := manager.standardMiddleware()

	t.Run("concurrent auth attempts are recorded correctly", func(t *testing.T) {
		metrics.Reset()
		audit.Reset()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		iterations := 50
		done := make(chan bool)

		for i := 0; i < iterations; i++ {
			go func() {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("X-API-Key", testKey.APIKey)
				rr := httptest.NewRecorder()

				middleware(handler).ServeHTTP(rr, req)
				done <- true
			}()
		}

		// Wait for all requests
		for i := 0; i < iterations; i++ {
			<-done
		}

		// All requests should be recorded
		assert.Equal(t, iterations, metrics.GetAuthAttemptCount())
		assert.Equal(t, iterations, metrics.GetAuthSuccessCount())
		assert.Equal(t, iterations, audit.GetAuthEventCount())
	})
}

func TestMiddleware_Observability_NilObservability(t *testing.T) {
	// Create manager without observability
	mockRepo := newMockRepository()
	logger, _ := zap.NewDevelopment()
	service, err := NewAPIKeyService(mockRepo, logger, DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH, 0, 0)
	require.NoError(t, err)

	// Don't set observability
	service.SetObservability(nil)

	config := &Config{
		Logger:       logger,
		ApiKeyPrefix: DEFAULT_APIKEY_PREFIX,
		ApiKeyLength: DEFAULT_APIKEY_LENGTH,
		HeaderKey:    "X-API-Key",
	}
	config.ApplyDefaults()

	manager := &APIKeyManager{
		config:        config,
		logger:        logger.Named(CLASS_APIKEY_MANAGER),
		service:       service,
		observability: nil,
	}

	// Create test key
	apiKeyInfo := &APIKeyInfo{
		UserID: "nil-test-user",
		OrgID:  "nil-test-org",
		Name:   "Nil Test Key",
	}
	created, _ := service.CreateAPIKey(context.Background(), apiKeyInfo)

	middleware := manager.standardMiddleware()

	t.Run("middleware works with nil observability", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-API-Key", created.APIKey)
		rr := httptest.NewRecorder()

		// Should not panic with nil observability
		assert.NotPanics(t, func() {
			middleware(handler).ServeHTTP(rr, req)
		})

		assert.Equal(t, http.StatusOK, rr.Code)
	})
}
