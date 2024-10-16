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

	manager.logger("INFO", "[GO-APIKEYS.RegisterFiberCRUDRoutes] Fiber CRUD routes registered")
}

// Fiber Handlers =============================================================

// FiberHandlers contains all the Fiber-specific handlers
type FiberHandlers struct {
	manager *APIKeyManager
}

func NewFiberHandlers(manager *APIKeyManager) *FiberHandlers {
	return &FiberHandlers{manager: manager}
}

// CreateAPIKey handles the creation of a new API key
func (h *FiberHandlers) CreateAPIKey(c *fiber.Ctx) error {
	if !isSystemAdminFiber(h.manager, c) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized: not a system admin"})
	}

	var apiKeyInfo APIKeyInfo
	if err := c.BodyParser(&apiKeyInfo); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid JSON"})
	}

	_, err := h.manager.CreateAPIKey(c.Context(), &apiKeyInfo)
	if err != nil {
		h.manager.logger("ERROR", "[GO-APIKEYS.CreateAPIKey] Error creating API key: "+err.Error())
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create API key"})
	}

	callerInfo := apiKeyInfo.Filter(true, false)
	h.manager.logger("INFO", "[GO-APIKEYS.CreateAPIKey] API key created: "+callerInfo.APIKeyHint)
	return c.Status(fiber.StatusCreated).JSON(callerInfo)
}

// SearchAPIKeys handles the search for API keys
func (h *FiberHandlers) SearchAPIKeys(c *fiber.Ctx) error {
	if !isSystemAdminFiber(h.manager, c) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized: not a system admin"})
	}

	apiKeyInfos, err := h.manager.SearchAPIKeys(c.Context(), 0, 1000)
	if err != nil {
		h.manager.logger("ERROR", "[GO-APIKEYS.SearchAPIKeys] Error searching API keys: "+err.Error())
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to search API keys"})
	}

	return c.Status(fiber.StatusOK).JSON(apiKeyInfos)
}

// GetAPIKey handles retrieving an API key by its value or hash
func (h *FiberHandlers) GetAPIKey(c *fiber.Ctx) error {
	if !isSystemAdminFiber(h.manager, c) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized: not a system admin"})
	}

	keyOrHash := c.Params("key_or_hash")
	if keyOrHash == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing API key or hash"})
	}

	apiKeyInfo, err := h.manager.GetAPIKeyInfo(c.Context(), keyOrHash)
	if err != nil {
		if err == ErrAPIKeyNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "API key not found"})
		}
		h.manager.logger("ERROR", "[GO-APIKEYS.GetAPIKey] Error retrieving API key: "+err.Error())
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve API key"})
	}

	return c.Status(fiber.StatusOK).JSON(apiKeyInfo)
}

// UpdateAPIKey handles updating an existing API key
func (h *FiberHandlers) UpdateAPIKey(c *fiber.Ctx) error {
	if !isSystemAdminFiber(h.manager, c) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized: not a system admin"})
	}

	keyOrHash := c.Params("key_or_hash")
	if keyOrHash == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing API key hash"})
	}

	var apiKeyInfo APIKeyInfo
	if err := c.BodyParser(&apiKeyInfo); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid JSON"})
	}
	apiKeyInfo.APIKeyHash = keyOrHash

	err := h.manager.UpdateAPIKey(c.Context(), &apiKeyInfo)
	if err != nil {
		h.manager.logger("ERROR", "[GO-APIKEYS.UpdateAPIKey] Error updating API key: "+err.Error())
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update API key"})
	}

	updatedDBKey, err := h.manager.GetAPIKeyInfo(c.Context(), keyOrHash)
	if err != nil {
		h.manager.logger("ERROR", "[GO-APIKEYS.UpdateAPIKey] Error retrieving updated API key: "+err.Error())
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve updated API key"})
	}

	return c.Status(fiber.StatusOK).JSON(updatedDBKey)
}

// DeleteAPIKey handles deleting an API key
func (h *FiberHandlers) DeleteAPIKey(c *fiber.Ctx) error {
	if !isSystemAdminFiber(h.manager, c) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized: not a system admin"})
	}

	keyOrHash := c.Params("key_or_hash")
	if keyOrHash == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing API key or hash"})
	}

	err := h.manager.DeleteAPIKey(c.Context(), keyOrHash)
	if err != nil {
		if err == ErrAPIKeyNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "API key not found"})
		}
		h.manager.logger("ERROR", "[GO-APIKEYS.DeleteAPIKey] Error deleting API key: "+err.Error())
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete API key"})
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// IsSystemAdmin checks if the current API key belongs to a system admin
func (h *FiberHandlers) IsSystemAdmin(c *fiber.Ctx) error {
	state := isSystemAdminFiber(h.manager, c)
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"isSystemAdmin": state})
}

// isSystemAdmin is a helper function to check if the request is from a system admin
func isSystemAdminFiber(manager *APIKeyManager, c *fiber.Ctx) bool {
	apiKeyInfo := manager.Get(c)
	if apiKeyInfo == nil {
		// manager.logger("INFO", "No ApiKeyInfo found in request context")
		return false
	}
	systemAdmin, ok := apiKeyInfo.Metadata[METADATA_KEYS_SYSTEM_ADMIN]
	if !ok {
		// manager.logger("INFO", "[GO-APIKEYS.isSystemAdmin] API key [METADATA_KEYS_SYSTEM_ADMIN] not found in context")
		return false
	}
	isSysAdmin, ok := systemAdmin.(bool)
	if !ok {
		// manager.logger("INFO", "[GO-APIKEYS.isSystemAdmin] API key systemAdmin metadata is not a boolean")
		return false
	}
	return isSysAdmin
}
