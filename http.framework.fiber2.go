package apikeys

import (
	"context"

	"github.com/gofiber/fiber/v2"
)

type FiberFramework struct{}

func (f *FiberFramework) GetRequestHeader(r interface{}, key string) string {
	return r.(*fiber.Ctx).Get(key)
}

func (f *FiberFramework) SetResponseHeader(w interface{}, key, value string) {
	w.(*fiber.Ctx).Set(key, value)
}

func (f *FiberFramework) GetRequestParam(r interface{}, key string) string {
	return r.(*fiber.Ctx).Params(key)
}

func (f *FiberFramework) WriteResponse(w interface{}, status int, body []byte) error {
	return w.(*fiber.Ctx).Status(status).Send(body)
}

func (f *FiberFramework) GetRequestContext(r interface{}) context.Context {
	return r.(*fiber.Ctx).UserContext()
}

func (f *FiberFramework) SetContextValue(r interface{}, key, value interface{}) {
	ctx := r.(*fiber.Ctx)
	ctx.Locals(string(key.(string)), value)
	// ctx.SetUserContext(newCtx)
}

func (f *FiberFramework) GetContextValue(r interface{}, key interface{}) interface{} {
	fctx, ok := r.(*fiber.Ctx)
	if !ok {
		return nil
	}
	keyString, ok := key.(string)
	if !ok {
		return nil
	}
	val := fctx.Locals(keyString)
	return val
}

func (f *FiberFramework) GetRequestPath(r interface{}) string {
	return r.(*fiber.Ctx).Path()
}

func (f *FiberFramework) WrapMiddleware(next interface{}) interface{} {
	return func(c *fiber.Ctx) error {
		if handlerFunc, ok := next.(func(interface{}, interface{})); ok {
			handlerFunc(c, c)
		}
		return c.Next() // This is crucial for Fiber to continue processing
	}
}

func (f *FiberFramework) FiberMiddleware(m *APIKeyManager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		middleware := m.Middleware().(func(*fiber.Ctx) error)
		return middleware(c)
	}
}

// Fiber Route-Registrations =============================================================

// RegisterFiberCRUDRoutes registers the CRUD routes for Fiber
func RegisterFiberCRUDRoutes(router fiber.Router, manager *APIKeyManager) {
	handlers := NewFiberHandlers(manager)

	router.Post("/apikeys", handlers.CreateAPIKey)
	router.Get("/apikeys/search", handlers.SearchAPIKeys)
	router.Get("/apikeys/issystemadmin", handlers.IsSystemAdmin)
	router.Get("/apikeys/:key_or_hash", handlers.GetAPIKey)
	router.Put("/apikeys/:key_or_hash", handlers.UpdateAPIKey)
	router.Delete("/apikeys/:key_or_hash", handlers.DeleteAPIKey)

	manager.logger.Info("[GO-APIKEYS.RegisterFiberCRUDRoutes] Fiber CRUD routes registered")
}

// Fiber Handlers =============================================================

// FiberHandlers contains all the Fiber-specific handlers
type FiberHandlers struct {
	manager *APIKeyManager
	core    *HandlerCore
}

func NewFiberHandlers(manager *APIKeyManager) *FiberHandlers {
	return &FiberHandlers{
		manager: manager,
		core:    NewHandlerCore(manager),
	}
}

// CreateAPIKey handles the creation of a new API key
func (h *FiberHandlers) CreateAPIKey(c *fiber.Ctx) error {
	// Extract request body
	body := c.Body()

	// Get API key info from context (for auth check)
	apiKeyInfo := h.manager.Get(c)

	// Call core handler
	result := h.core.HandleCreateAPIKey(c.Context(), body, apiKeyInfo)

	// Convert result to Fiber response
	return fiberResponse(c, result)
}

// SearchAPIKeys handles the search for API keys
func (h *FiberHandlers) SearchAPIKeys(c *fiber.Ctx) error {
	apiKeyInfo := h.manager.Get(c)
	result := h.core.HandleSearchAPIKeys(c.Context(), apiKeyInfo)
	return fiberResponse(c, result)
}

// GetAPIKey handles retrieving an API key by its value or hash
func (h *FiberHandlers) GetAPIKey(c *fiber.Ctx) error {
	keyOrHash := c.Params("key_or_hash")
	apiKeyInfo := h.manager.Get(c)
	result := h.core.HandleGetAPIKey(c.Context(), keyOrHash, apiKeyInfo)
	return fiberResponse(c, result)
}

// UpdateAPIKey handles updating an existing API key
func (h *FiberHandlers) UpdateAPIKey(c *fiber.Ctx) error {
	keyOrHash := c.Params("key_or_hash")
	body := c.Body()
	apiKeyInfo := h.manager.Get(c)
	result := h.core.HandleUpdateAPIKey(c.Context(), keyOrHash, body, apiKeyInfo)
	return fiberResponse(c, result)
}

// DeleteAPIKey handles deleting an API key
func (h *FiberHandlers) DeleteAPIKey(c *fiber.Ctx) error {
	keyOrHash := c.Params("key_or_hash")
	apiKeyInfo := h.manager.Get(c)
	result := h.core.HandleDeleteAPIKey(c.Context(), keyOrHash, apiKeyInfo)
	return fiberResponse(c, result)
}

// IsSystemAdmin checks if the current API key belongs to a system admin
func (h *FiberHandlers) IsSystemAdmin(c *fiber.Ctx) error {
	apiKeyInfo := h.manager.Get(c)
	result := h.core.HandleIsSystemAdmin(apiKeyInfo)
	return fiberResponse(c, result)
}

// fiberResponse converts a HandlerResult to a Fiber response
func fiberResponse(c *fiber.Ctx, result *HandlerResult) error {
	if result.Error != "" {
		return c.Status(result.StatusCode).JSON(fiber.Map{
			RESPONSE_KEY_ERROR: result.Error,
		})
	}

	if result.StatusCode == 204 {
		return c.SendStatus(fiber.StatusNoContent)
	}

	return c.Status(result.StatusCode).JSON(result.Data)
}
