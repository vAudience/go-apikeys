package apikeys

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// FiberFramework Interface Tests (12 tests)
// =============================================================================

func TestFiberFramework_GetRequestHeader(t *testing.T) {
	fw := &FiberFramework{}

	t.Run("header exists", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			value := fw.GetRequestHeader(c, "X-Test-Header")
			assert.Equal(t, "test-value", value)
			return c.SendStatus(200)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Test-Header", "test-value")
		_, err := app.Test(req)
		require.NoError(t, err)
	})

	t.Run("header doesn't exist", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			value := fw.GetRequestHeader(c, "X-Missing-Header")
			assert.Empty(t, value)
			return c.SendStatus(200)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		_, err := app.Test(req)
		require.NoError(t, err)
	})

	t.Run("case-insensitive header", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			value := fw.GetRequestHeader(c, "x-test-header")
			assert.Equal(t, "test-value", value)
			return c.SendStatus(200)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Test-Header", "test-value")
		_, err := app.Test(req)
		require.NoError(t, err)
	})
}

func TestFiberFramework_SetResponseHeader(t *testing.T) {
	fw := &FiberFramework{}

	t.Run("set single header", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			fw.SetResponseHeader(c, "X-Custom-Header", "custom-value")
			return c.SendStatus(200)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, "custom-value", resp.Header.Get("X-Custom-Header"))
	})

	t.Run("overwrite existing header", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			c.Set("X-Custom-Header", "old-value")
			fw.SetResponseHeader(c, "X-Custom-Header", "new-value")
			return c.SendStatus(200)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, "new-value", resp.Header.Get("X-Custom-Header"))
	})
}

func TestFiberFramework_GetRequestParam(t *testing.T) {
	fw := &FiberFramework{}

	t.Run("param exists", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test/:id", func(c *fiber.Ctx) error {
			value := fw.GetRequestParam(c, "id")
			assert.Equal(t, "123", value)
			return c.SendStatus(200)
		})

		req := httptest.NewRequest("GET", "/test/123", nil)
		_, err := app.Test(req)
		require.NoError(t, err)
	})

	t.Run("param doesn't exist", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			value := fw.GetRequestParam(c, "id")
			assert.Empty(t, value)
			return c.SendStatus(200)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		_, err := app.Test(req)
		require.NoError(t, err)
	})

	t.Run("multiple params", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test/:org/:user", func(c *fiber.Ctx) error {
			org := fw.GetRequestParam(c, "org")
			user := fw.GetRequestParam(c, "user")
			assert.Equal(t, "myorg", org)
			assert.Equal(t, "myuser", user)
			return c.SendStatus(200)
		})

		req := httptest.NewRequest("GET", "/test/myorg/myuser", nil)
		_, err := app.Test(req)
		require.NoError(t, err)
	})
}

func TestFiberFramework_WriteResponse(t *testing.T) {
	fw := &FiberFramework{}

	t.Run("write success response", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			body := []byte(`{"message":"success"}`)
			return fw.WriteResponse(c, 200, body)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)

		var result map[string]string
		json.NewDecoder(resp.Body).Decode(&result)
		assert.Equal(t, "success", result["message"])
	})

	t.Run("write error response", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			body := []byte(`{"error":"not found"}`)
			return fw.WriteResponse(c, 404, body)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, 404, resp.StatusCode)
	})

	t.Run("write empty body", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			return fw.WriteResponse(c, 204, []byte{})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, 204, resp.StatusCode)
	})
}

func TestFiberFramework_GetRequestContext(t *testing.T) {
	fw := &FiberFramework{}

	t.Run("get context", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			ctx := fw.GetRequestContext(c)
			assert.NotNil(t, ctx)
			assert.IsType(t, context.Background(), ctx)
			return c.SendStatus(200)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		_, err := app.Test(req)
		require.NoError(t, err)
	})

	t.Run("context with values", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			// Set a value in user context
			ctx := context.WithValue(c.UserContext(), "key", "value")
			c.SetUserContext(ctx)

			// Get context via framework
			retrievedCtx := fw.GetRequestContext(c)
			assert.Equal(t, "value", retrievedCtx.Value("key"))
			return c.SendStatus(200)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		_, err := app.Test(req)
		require.NoError(t, err)
	})
}

func TestFiberFramework_SetContextValue(t *testing.T) {
	fw := &FiberFramework{}

	t.Run("set and retrieve value", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			fw.SetContextValue(c, "test_key", "test_value")
			value := c.Locals("test_key")
			assert.Equal(t, "test_value", value)
			return c.SendStatus(200)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		_, err := app.Test(req)
		require.NoError(t, err)
	})

	t.Run("overwrite existing value", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			c.Locals("test_key", "old_value")
			fw.SetContextValue(c, "test_key", "new_value")
			value := c.Locals("test_key")
			assert.Equal(t, "new_value", value)
			return c.SendStatus(200)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		_, err := app.Test(req)
		require.NoError(t, err)
	})

	t.Run("set APIKeyInfo struct", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			apiKeyInfo := &APIKeyInfo{
				UserID: "test-user",
				OrgID:  "test-org",
			}
			fw.SetContextValue(c, LOCALS_KEY_APIKEYS, apiKeyInfo)

			retrieved := c.Locals(LOCALS_KEY_APIKEYS)
			assert.NotNil(t, retrieved)
			assert.Equal(t, "test-user", retrieved.(*APIKeyInfo).UserID)
			return c.SendStatus(200)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		_, err := app.Test(req)
		require.NoError(t, err)
	})
}

func TestFiberFramework_GetContextValue(t *testing.T) {
	fw := &FiberFramework{}

	t.Run("value exists", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			c.Locals("test_key", "test_value")
			value := fw.GetContextValue(c, "test_key")
			assert.Equal(t, "test_value", value)
			return c.SendStatus(200)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		_, err := app.Test(req)
		require.NoError(t, err)
	})

	t.Run("value doesn't exist", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			value := fw.GetContextValue(c, "missing_key")
			assert.Nil(t, value)
			return c.SendStatus(200)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		_, err := app.Test(req)
		require.NoError(t, err)
	})

	t.Run("wrong context type", func(t *testing.T) {
		fw := &FiberFramework{}
		value := fw.GetContextValue("not-a-fiber-context", "key")
		assert.Nil(t, value)
	})

	t.Run("wrong key type", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			value := fw.GetContextValue(c, 123) // Integer key, not string
			assert.Nil(t, value)
			return c.SendStatus(200)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		_, err := app.Test(req)
		require.NoError(t, err)
	})
}

func TestFiberFramework_GetRequestPath(t *testing.T) {
	fw := &FiberFramework{}

	t.Run("simple path", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			path := fw.GetRequestPath(c)
			assert.Equal(t, "/test", path)
			return c.SendStatus(200)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		_, err := app.Test(req)
		require.NoError(t, err)
	})

	t.Run("path with params", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test/:id", func(c *fiber.Ctx) error {
			path := fw.GetRequestPath(c)
			// Fiber's Path() returns the actual path, not the route pattern
			assert.Equal(t, "/test/123", path)
			return c.SendStatus(200)
		})

		req := httptest.NewRequest("GET", "/test/123", nil)
		_, err := app.Test(req)
		require.NoError(t, err)
	})

	t.Run("path with query string", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			path := fw.GetRequestPath(c)
			assert.Equal(t, "/test", path) // Path() doesn't include query string
			return c.SendStatus(200)
		})

		req := httptest.NewRequest("GET", "/test?foo=bar", nil)
		_, err := app.Test(req)
		require.NoError(t, err)
	})
}

// =============================================================================
// fiberResponse Helper Tests (3 tests)
// =============================================================================

func TestFiberResponse(t *testing.T) {
	t.Run("success with data", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			result := &HandlerResult{
				StatusCode: 200,
				Data:       map[string]string{"message": "success"},
			}
			return fiberResponse(c, result)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
	})

	t.Run("error response", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			result := &HandlerResult{
				StatusCode: 400,
				Error:      "bad request",
			}
			return fiberResponse(c, result)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, 400, resp.StatusCode)

		var result map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&result)
		assert.Equal(t, "bad request", result[RESPONSE_KEY_ERROR])
	})

	t.Run("204 no content", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			result := &HandlerResult{
				StatusCode: 204,
			}
			return fiberResponse(c, result)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, 204, resp.StatusCode)
	})
}

// Note: FiberHandlers and RegisterFiberCRUDRoutes require full integration testing
// with a real APIKeyManager and repository. These are better tested in integration tests
// or example applications. The framework interface methods above provide comprehensive
// coverage of the Fiber adapter's core functionality.
