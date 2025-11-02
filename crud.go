package apikeys

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/gofiber/fiber/v2"
)

// StandardHandlers contains all the standard http.HandlerFunc handlers
type StandardHandlers struct {
	manager *APIKeyManager
	core    *HandlerCore
}

func NewStandardHandlers(manager *APIKeyManager) *StandardHandlers {
	return &StandardHandlers{
		manager: manager,
		core:    NewHandlerCore(manager),
	}
}

// stdlibResponse converts a HandlerResult to an http.ResponseWriter response
func stdlibResponse(w http.ResponseWriter, result *HandlerResult) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(result.StatusCode)

	if result.Error != "" {
		json.NewEncoder(w).Encode(map[string]string{
			RESPONSE_KEY_ERROR: result.Error,
		})
		return
	}

	if result.StatusCode == http.StatusNoContent {
		return
	}

	if result.Data != nil {
		json.NewEncoder(w).Encode(result.Data)
	}
}

// createAPIKey godoc
// @Summary Create a new API key
// @Description Create a new API key
// @Tags APIKeys
// @Accept json
// @Produce json
// @Param apiKeyInfo body APIKeyInfo true "API key information"
// @Success 201 {object} APIKeyInfo
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /apikeys [post]
// @Security ApiKey
func (h *StandardHandlers) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	defer r.Body.Close()
	apiKeyInfo := h.manager.Get(r)
	result := h.core.HandleCreateAPIKey(r.Context(), body, apiKeyInfo)
	stdlibResponse(w, result)
}

// searchAPIKeys godoc
// @Summary Search API keys
// @Description Search for API keys based on a query string
// @Tags APIKeys
// @Accept json
// @Produce json
// @Success 200 {array} APIKeyInfo
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /apikeys/search [get]
// @Security ApiKey
func (h *StandardHandlers) SearchAPIKeys(w http.ResponseWriter, r *http.Request) {
	apiKeyInfo := h.manager.Get(r)
	result := h.core.HandleSearchAPIKeys(r.Context(), apiKeyInfo)
	stdlibResponse(w, result)
}

// getAPIKey godoc
// @Summary Get APIKeyInfo by the API key or its hash
// @Description Retrieve APIKeyInfo by the API key or its hash
// @Tags APIKeys
// @Accept json
// @Produce json
// @Param key_or_hash path string true "API key value or hash"
// @Success 200 {object} APIKeyInfo
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /apikeys/{key_or_hash} [get]
// @Security ApiKey
func (h *StandardHandlers) GetAPIKey(w http.ResponseWriter, r *http.Request) {
	keyOrHash := r.PathValue("key_or_hash")
	apiKeyInfo := h.manager.Get(r)
	result := h.core.HandleGetAPIKey(r.Context(), keyOrHash, apiKeyInfo)
	stdlibResponse(w, result)
}

// updateAPIKey godoc
// @Summary Update an existing API key
// @Description Update an existing API key with new information
// @Tags APIKeys
// @Accept json
// @Produce json
// @Param key_or_hash path string true "API key hash"
// @Param apiKeyInfo body APIKeyInfo true "Updated API key information"
// @Success 200 {object} APIKeyInfo
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /apikeys/{key_or_hash} [put]
// @Security ApiKey
func (h *StandardHandlers) UpdateAPIKey(w http.ResponseWriter, r *http.Request) {
	keyOrHash := r.PathValue("key_or_hash")
	body, _ := io.ReadAll(r.Body)
	defer r.Body.Close()
	apiKeyInfo := h.manager.Get(r)
	result := h.core.HandleUpdateAPIKey(r.Context(), keyOrHash, body, apiKeyInfo)
	stdlibResponse(w, result)
}

// deleteAPIKey godoc
// @Summary Delete an API key
// @Description Delete an API key by its value or hash
// @Tags APIKeys
// @Accept json
// @Produce json
// @Param key_or_hash path string true "API key value or hash"
// @Success 204 "API key deleted successfully"
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /apikeys/{key_or_hash} [delete]
// @Security ApiKey
func (h *StandardHandlers) DeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	keyOrHash := r.PathValue("key_or_hash")
	apiKeyInfo := h.manager.Get(r)
	result := h.core.HandleDeleteAPIKey(r.Context(), keyOrHash, apiKeyInfo)
	stdlibResponse(w, result)
}

// isSystemAdminHandler godoc
// @Summary Check if the API key belongs to a system admin
// @Description Determine if the API key in the request context has system admin privileges
// @Tags APIKeys
// @Accept json
// @Produce json
// @Success 200 {object} map[string]bool
// @Failure 401 {object} ErrorResponse
// @Router /apikeys/issystemadmin [get]
// @Security ApiKey
func (h *StandardHandlers) IsSystemAdmin(w http.ResponseWriter, r *http.Request) {
	apiKeyInfo := h.manager.Get(r)
	result := h.core.HandleIsSystemAdmin(apiKeyInfo)
	stdlibResponse(w, result)
}

func RegisterCRUDRoutes(router interface{}, apikeyManager *APIKeyManager) {
	switch r := router.(type) {
	case *http.ServeMux:
		handlers := NewStandardHandlers(apikeyManager)
		r.HandleFunc("/apikeys", handlers.CreateAPIKey)
		r.HandleFunc("/apikeys/search", handlers.SearchAPIKeys)
		r.HandleFunc("/apikeys/issystemadmin", handlers.IsSystemAdmin)
		r.HandleFunc("/apikeys/{key_or_hash}", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				handlers.GetAPIKey(w, r)
			case http.MethodPut:
				handlers.UpdateAPIKey(w, r)
			case http.MethodDelete:
				handlers.DeleteAPIKey(w, r)
			default:
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})
	case fiber.Router:
		// Fiber routes are handled in http.framework.fiber2.go
		RegisterFiberCRUDRoutes(r, apikeyManager)
	default:
		apikeyManager.logger.Error(LOG_MSG_UNSUPPORTED_ROUTER)
		return
	}
	apikeyManager.logger.Info(LOG_MSG_CRUD_ROUTES_REGISTERED)
}

// NOTE: ErrorResponse, GenerateAPIKey, GenerateAPIKeyHash, IsApiKey
// are now defined in apikeys.errors.go and apikeys.helpers.go
