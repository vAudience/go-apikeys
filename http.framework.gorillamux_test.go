package apikeys

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// GorillaMuxFramework Interface Tests (26 tests)
// =============================================================================

func TestGorillaMuxFramework_GetRequestHeader(t *testing.T) {
	fw := &GorillaMuxFramework{}

	t.Run("header exists", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Test-Header", "test-value")

		value := fw.GetRequestHeader(req, "X-Test-Header")
		assert.Equal(t, "test-value", value)
	})

	t.Run("header doesn't exist", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)

		value := fw.GetRequestHeader(req, "X-Missing-Header")
		assert.Empty(t, value)
	})

	t.Run("case-insensitive header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Test-Header", "test-value")

		// HTTP headers are case-insensitive
		value := fw.GetRequestHeader(req, "x-test-header")
		assert.Equal(t, "test-value", value)
	})
}

func TestGorillaMuxFramework_SetResponseHeader(t *testing.T) {
	fw := &GorillaMuxFramework{}

	t.Run("set single header", func(t *testing.T) {
		w := httptest.NewRecorder()
		fw.SetResponseHeader(w, "X-Custom-Header", "custom-value")

		assert.Equal(t, "custom-value", w.Header().Get("X-Custom-Header"))
	})

	t.Run("overwrite existing header", func(t *testing.T) {
		w := httptest.NewRecorder()
		w.Header().Set("X-Custom-Header", "old-value")
		fw.SetResponseHeader(w, "X-Custom-Header", "new-value")

		assert.Equal(t, "new-value", w.Header().Get("X-Custom-Header"))
	})

	t.Run("wrong type doesn't panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			fw.SetResponseHeader("not-a-response-writer", "key", "value")
		})
	})
}

func TestGorillaMuxFramework_GetRequestParam(t *testing.T) {
	fw := &GorillaMuxFramework{}

	t.Run("param exists", func(t *testing.T) {
		router := mux.NewRouter()
		router.HandleFunc("/test/{id}", func(w http.ResponseWriter, r *http.Request) {
			value := fw.GetRequestParam(r, "id")
			assert.Equal(t, "123", value)
			w.WriteHeader(200)
		})

		req := httptest.NewRequest("GET", "/test/123", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	})

	t.Run("param doesn't exist", func(t *testing.T) {
		router := mux.NewRouter()
		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			value := fw.GetRequestParam(r, "id")
			assert.Empty(t, value)
			w.WriteHeader(200)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	})

	t.Run("multiple params", func(t *testing.T) {
		router := mux.NewRouter()
		router.HandleFunc("/test/{org}/{user}", func(w http.ResponseWriter, r *http.Request) {
			org := fw.GetRequestParam(r, "org")
			user := fw.GetRequestParam(r, "user")
			assert.Equal(t, "myorg", org)
			assert.Equal(t, "myuser", user)
			w.WriteHeader(200)
		})

		req := httptest.NewRequest("GET", "/test/myorg/myuser", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	})
}

func TestGorillaMuxFramework_WriteResponse(t *testing.T) {
	fw := &GorillaMuxFramework{}

	t.Run("write success response", func(t *testing.T) {
		w := httptest.NewRecorder()
		body := []byte(`{"message":"success"}`)

		err := fw.WriteResponse(w, 200, body)
		require.NoError(t, err)
		assert.Equal(t, 200, w.Code)
		assert.Equal(t, `{"message":"success"}`, w.Body.String())
	})

	t.Run("write error response", func(t *testing.T) {
		w := httptest.NewRecorder()
		body := []byte(`{"error":"not found"}`)

		err := fw.WriteResponse(w, 404, body)
		require.NoError(t, err)
		assert.Equal(t, 404, w.Code)
		assert.Equal(t, `{"error":"not found"}`, w.Body.String())
	})

	t.Run("write empty body", func(t *testing.T) {
		w := httptest.NewRecorder()

		err := fw.WriteResponse(w, 204, []byte{})
		require.NoError(t, err)
		assert.Equal(t, 204, w.Code)
		assert.Empty(t, w.Body.String())
	})

	t.Run("wrong type doesn't error", func(t *testing.T) {
		err := fw.WriteResponse("not-a-response-writer", 200, []byte("test"))
		assert.NoError(t, err) // Returns nil for wrong type
	})
}

func TestGorillaMuxFramework_GetRequestContext(t *testing.T) {
	fw := &GorillaMuxFramework{}

	t.Run("get context", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		ctx := fw.GetRequestContext(req)

		assert.NotNil(t, ctx)
		assert.IsType(t, context.Background(), ctx)
	})

	t.Run("context with values", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		ctx := context.WithValue(req.Context(), "key", "value")
		req = req.WithContext(ctx)

		retrievedCtx := fw.GetRequestContext(req)
		assert.Equal(t, "value", retrievedCtx.Value("key"))
	})
}

func TestGorillaMuxFramework_SetContextValue(t *testing.T) {
	fw := &GorillaMuxFramework{}

	t.Run("set and retrieve value", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		fw.SetContextValue(req, "test_key", "test_value")

		value := req.Context().Value("test_key")
		assert.Equal(t, "test_value", value)
	})

	t.Run("overwrite existing value", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		ctx := context.WithValue(req.Context(), "test_key", "old_value")
		req = req.WithContext(ctx)

		fw.SetContextValue(req, "test_key", "new_value")
		value := req.Context().Value("test_key")
		assert.Equal(t, "new_value", value)
	})

	t.Run("chain multiple values", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		fw.SetContextValue(req, "key1", "value1")
		fw.SetContextValue(req, "key2", "value2")

		assert.Equal(t, "value1", req.Context().Value("key1"))
		assert.Equal(t, "value2", req.Context().Value("key2"))
	})

	t.Run("set APIKeyInfo struct", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		apiKeyInfo := &APIKeyInfo{
			UserID: "test-user",
			OrgID:  "test-org",
		}

		fw.SetContextValue(req, contextKeyAPIKeyInfo, apiKeyInfo)
		retrieved := req.Context().Value(contextKeyAPIKeyInfo)

		assert.NotNil(t, retrieved)
		assert.Equal(t, "test-user", retrieved.(*APIKeyInfo).UserID)
	})
}

func TestGorillaMuxFramework_GetContextValue(t *testing.T) {
	fw := &GorillaMuxFramework{}

	t.Run("value exists", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		ctx := context.WithValue(req.Context(), "test_key", "test_value")
		req = req.WithContext(ctx)

		value := fw.GetContextValue(req, "test_key")
		assert.Equal(t, "test_value", value)
	})

	t.Run("value doesn't exist", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)

		value := fw.GetContextValue(req, "missing_key")
		assert.Nil(t, value)
	})

	t.Run("with typed context key", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		ctx := context.WithValue(req.Context(), contextKeyAPIKeyInfo, "typed-value")
		req = req.WithContext(ctx)

		value := fw.GetContextValue(req, contextKeyAPIKeyInfo)
		assert.Equal(t, "typed-value", value)
	})
}

func TestGorillaMuxFramework_GetRequestPath(t *testing.T) {
	fw := &GorillaMuxFramework{}

	t.Run("simple path", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		path := fw.GetRequestPath(req)
		assert.Equal(t, "/test", path)
	})

	t.Run("path with params", func(t *testing.T) {
		// Even with mux routing, URL.Path shows the actual path
		req := httptest.NewRequest("GET", "/test/123", nil)
		path := fw.GetRequestPath(req)
		assert.Equal(t, "/test/123", path)
	})

	t.Run("path with query string", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test?foo=bar&baz=qux", nil)
		path := fw.GetRequestPath(req)
		// URL.Path doesn't include query string
		assert.Equal(t, "/test", path)
	})

	t.Run("root path", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		path := fw.GetRequestPath(req)
		assert.Equal(t, "/", path)
	})
}

func TestGorillaMuxFramework_WrapMiddleware(t *testing.T) {
	fw := &GorillaMuxFramework{}

	t.Run("wraps handler correctly", func(t *testing.T) {
		called := false
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(200)
		})

		wrapped := fw.WrapMiddleware(handler)
		wrappedFunc, ok := wrapped.(func(http.ResponseWriter, *http.Request))
		require.True(t, ok, "Wrapped middleware should be http.HandlerFunc")

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		wrappedFunc(w, req)

		assert.True(t, called, "Handler should have been called")
	})

	t.Run("handler receives request and response", func(t *testing.T) {
		var receivedReq *http.Request
		var receivedW http.ResponseWriter

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedW = w
			receivedReq = r
			w.WriteHeader(200)
		})

		wrapped := fw.WrapMiddleware(handler)
		wrappedFunc := wrapped.(func(http.ResponseWriter, *http.Request))

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		wrappedFunc(w, req)

		assert.NotNil(t, receivedReq)
		assert.NotNil(t, receivedW)
		assert.Equal(t, req, receivedReq)
	})
}

// =============================================================================
// Integration Tests with Gorilla Mux Router (3 tests)
// =============================================================================

func TestGorillaMuxFramework_Integration(t *testing.T) {
	fw := &GorillaMuxFramework{}

	t.Run("full request lifecycle", func(t *testing.T) {
		router := mux.NewRouter()

		// Handler that uses all framework methods
		router.HandleFunc("/test/{id}", func(w http.ResponseWriter, r *http.Request) {
			// Get header
			authHeader := fw.GetRequestHeader(r, "Authorization")
			assert.Equal(t, "Bearer token123", authHeader)

			// Get param
			id := fw.GetRequestParam(r, "id")
			assert.Equal(t, "456", id)

			// Get path
			path := fw.GetRequestPath(r)
			assert.Equal(t, "/test/456", path)

			// Set context value
			fw.SetContextValue(r, "user_id", "test-user")

			// Get context value
			userID := fw.GetContextValue(r, "user_id")
			assert.Equal(t, "test-user", userID)

			// Set response header
			fw.SetResponseHeader(w, "X-Request-ID", "req-123")

			// Write response
			body := []byte(`{"status":"success"}`)
			err := fw.WriteResponse(w, 200, body)
			assert.NoError(t, err)
		})

		req := httptest.NewRequest("GET", "/test/456", nil)
		req.Header.Set("Authorization", "Bearer token123")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		assert.Equal(t, "req-123", w.Header().Get("X-Request-ID"))
		assert.Equal(t, `{"status":"success"}`, w.Body.String())
	})

	t.Run("context propagation through middleware", func(t *testing.T) {
		router := mux.NewRouter()

		// Middleware that sets context value
		middleware := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fw.SetContextValue(r, "middleware_key", "middleware_value")
				next.ServeHTTP(w, r)
			})
		}

		router.Use(middleware)

		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			value := fw.GetContextValue(r, "middleware_key")
			assert.Equal(t, "middleware_value", value)
			w.WriteHeader(200)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
	})

	t.Run("error handling", func(t *testing.T) {
		router := mux.NewRouter()

		router.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) {
			fw.SetResponseHeader(w, "X-Error-Type", "test-error")

			errorBody := []byte(`{"error":"something went wrong"}`)
			err := fw.WriteResponse(w, 500, errorBody)
			assert.NoError(t, err)
		})

		req := httptest.NewRequest("GET", "/error", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 500, w.Code)
		assert.Equal(t, "test-error", w.Header().Get("X-Error-Type"))
		assert.Contains(t, w.Body.String(), "something went wrong")
	})
}

// =============================================================================
// Edge Cases and Error Handling (4 tests)
// =============================================================================

func TestGorillaMuxFramework_EdgeCases(t *testing.T) {
	fw := &GorillaMuxFramework{}

	t.Run("root request path", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		path := fw.GetRequestPath(req)
		assert.Equal(t, "/", path)
	})

	t.Run("nil context value", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		fw.SetContextValue(req, "nil_key", nil)

		value := fw.GetContextValue(req, "nil_key")
		assert.Nil(t, value)
	})

	t.Run("multiple header values", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Add("X-Multi", "value1")
		req.Header.Add("X-Multi", "value2")

		// Get returns the first value
		value := fw.GetRequestHeader(req, "X-Multi")
		assert.Equal(t, "value1", value)
	})

	t.Run("special characters in params", func(t *testing.T) {
		router := mux.NewRouter()
		router.HandleFunc("/test/{id}", func(w http.ResponseWriter, r *http.Request) {
			id := fw.GetRequestParam(r, "id")
			assert.Equal(t, "test-id-123", id)
			w.WriteHeader(200)
		})

		req := httptest.NewRequest("GET", "/test/test-id-123", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	})
}

// =============================================================================
// Type Safety Tests (2 tests)
// =============================================================================

func TestGorillaMuxFramework_TypeSafety(t *testing.T) {
	fw := &GorillaMuxFramework{}

	t.Run("context key type safety", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)

		// String key
		fw.SetContextValue(req, "string_key", "string_value")
		assert.Equal(t, "string_value", fw.GetContextValue(req, "string_key"))

		// Typed key (contextKey)
		fw.SetContextValue(req, contextKeyAPIKeyInfo, "typed_value")
		assert.Equal(t, "typed_value", fw.GetContextValue(req, contextKeyAPIKeyInfo))

		// Integer key
		fw.SetContextValue(req, 42, "int_value")
		assert.Equal(t, "int_value", fw.GetContextValue(req, 42))
	})

	t.Run("response writer type checking", func(t *testing.T) {
		// Valid ResponseWriter
		w := httptest.NewRecorder()
		fw.SetResponseHeader(w, "X-Test", "test")
		assert.Equal(t, "test", w.Header().Get("X-Test"))

		// Invalid type (shouldn't panic)
		assert.NotPanics(t, func() {
			fw.SetResponseHeader("not-a-writer", "X-Test", "test")
		})

		// WriteResponse with invalid type
		err := fw.WriteResponse("not-a-writer", 200, []byte("test"))
		assert.NoError(t, err) // Returns nil instead of panicking
	})
}
