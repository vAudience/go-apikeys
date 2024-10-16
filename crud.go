package apikeys

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/gofiber/fiber/v2"
	gonanoid "github.com/matoous/go-nanoid/v2"
	"golang.org/x/crypto/sha3"
)

// StandardHandlers contains all the standard http.HandlerFunc handlers
type StandardHandlers struct {
	manager *APIKeyManager
}

func NewStandardHandlers(manager *APIKeyManager) *StandardHandlers {
	return &StandardHandlers{manager: manager}
}

// Helper function to handle responses
func handleResponse(apikeyManager *APIKeyManager, w http.ResponseWriter, statusCode int, data interface{}) {
	// apikeyManager.logger("DEBUG", fmt.Sprintf("handleResponse called with status code: %d and data: %+v", statusCode, data))
	response, err := json.Marshal(data)
	if err != nil {
		apikeyManager.logger("ERROR", fmt.Sprintf("[apikeys.handleResponse] Failed to marshal apikeys response: %v", err))
		handleError(apikeyManager, w, http.StatusInternalServerError, "Internal server error")
		return
	}

	// apikeyManager.logger("DEBUG", fmt.Sprintf("Sending response: %s", string(response)))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, err = w.Write(response)
	if err != nil {
		apikeyManager.logger("ERROR", fmt.Sprintf("[apikeys.handleResponse] Failed to write response: %v", err))
	}
	// apikeyManager.logger("DEBUG", fmt.Sprintf("Response sent from handleResponse with status code: %d", statusCode))
}

// Helper function to handle errors
func handleError(apikeyManager *APIKeyManager, w http.ResponseWriter, statusCode int, message string) {
	errorResponse := ErrorResponse{Error: message}
	handleResponse(apikeyManager, w, statusCode, errorResponse)
}

// Helper function to get request data
func getRequestData(r *http.Request) (apiKey string, params map[string]string, body []byte) {
	params = make(map[string]string)
	apiKey = r.Header.Get("X-API-Key")
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			params[k] = v[0]
		}
	}
	json.NewDecoder(r.Body).Decode(&params)
	return
}

// isSystemAdmin checks if the request is from a system admin
func isSystemAdmin(apikeyManager *APIKeyManager, r *http.Request) bool {
	apiKeyInfo := apikeyManager.Get(r)
	if apiKeyInfo == nil {
		// apikeyManager.logger("INFO", "No ApiKeyInfo found in request context")
		return false
	}
	systemAdmin, ok := apiKeyInfo.Metadata[METADATA_KEYS_SYSTEM_ADMIN]
	if !ok {
		// apikeyManager.logger("INFO", fmt.Sprintf("[GO-APIKEYS.isSystemAdmin] API key [METADATA_KEYS_SYSTEM_ADMIN] not found in context:%v", apiKeyInfo))
		return false
	}
	isSysAdmin, ok := systemAdmin.(bool)
	if !ok {
		// apikeyManager.logger("INFO", fmt.Sprintf("[GO-APIKEYS.isSystemAdmin] API key systemAdmin metadata is not a boolean:(%v)", systemAdmin))
		return false
	}
	return isSysAdmin
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
	if !isSystemAdmin(h.manager, r) {
		handleError(h.manager, w, http.StatusUnauthorized, "Unauthorized: not a system admin")
		return
	}

	_, _, body := getRequestData(r)
	var apiKeyInfo APIKeyInfo
	if err := json.Unmarshal(body, &apiKeyInfo); err != nil {
		handleError(h.manager, w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	_, err := h.manager.CreateAPIKey(r.Context(), &apiKeyInfo)
	if err != nil {
		h.manager.logger("ERROR", fmt.Sprintf("[GO-APIKEYS.createAPIKey] Error creating API key: %v", err))
		handleError(h.manager, w, http.StatusInternalServerError, "Failed to create API key")
		return
	}

	callerInfo := apiKeyInfo.Filter(true, false)
	// h.manager.logger("INFO", fmt.Sprintf("[GO-APIKEYS.createAPIKey] API key(%s) created: %v", apiKeyInfo.APIKey, callerInfo))
	handleResponse(h.manager, w, http.StatusCreated, callerInfo)
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
	if !isSystemAdmin(h.manager, r) {
		handleError(h.manager, w, http.StatusUnauthorized, "Unauthorized: not a system admin")
		return
	}

	apiKeyInfos, err := h.manager.SearchAPIKeys(r.Context(), 0, 1000)
	if err != nil {
		h.manager.logger("ERROR", fmt.Sprintf("[GO-APIKEYS.searchAPIKeys] Error searching API keys: %v", err))
		handleError(h.manager, w, http.StatusInternalServerError, "Failed to search API keys")
		return
	}

	handleResponse(h.manager, w, http.StatusOK, apiKeyInfos)
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
	if !isSystemAdmin(h.manager, r) {
		handleError(h.manager, w, http.StatusUnauthorized, "Unauthorized: not a system admin")
		return
	}

	_, params, _ := getRequestData(r)
	keyOrHash := params["key_or_hash"]
	if keyOrHash == "" {
		handleError(h.manager, w, http.StatusBadRequest, "Missing API key or hash")
		return
	}

	apiKeyInfo, err := h.manager.GetAPIKeyInfo(r.Context(), keyOrHash)
	if err != nil {
		if err == ErrAPIKeyNotFound {
			handleError(h.manager, w, http.StatusNotFound, "API key not found")
		} else {
			h.manager.logger("ERROR", fmt.Sprintf("[GO-APIKEYS.getAPIKey] Error retrieving API key: %v", err))
			handleError(h.manager, w, http.StatusInternalServerError, "Failed to retrieve API key")
		}
		return
	}

	handleResponse(h.manager, w, http.StatusOK, apiKeyInfo)
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
	if !isSystemAdmin(h.manager, r) {
		handleError(h.manager, w, http.StatusUnauthorized, "Unauthorized: not a system admin")
		return
	}

	_, params, body := getRequestData(r)
	keyOrHash := params["key_or_hash"]
	if keyOrHash == "" {
		handleError(h.manager, w, http.StatusBadRequest, "Missing API key hash")
		return
	}

	var apiKeyInfo APIKeyInfo
	if err := json.Unmarshal(body, &apiKeyInfo); err != nil {
		handleError(h.manager, w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	apiKeyInfo.APIKeyHash = keyOrHash

	err := h.manager.UpdateAPIKey(r.Context(), &apiKeyInfo)
	if err != nil {
		h.manager.logger("ERROR", fmt.Sprintf("[GO-APIKEYS.updateAPIKey] Error updating API key: %v", err))
		handleError(h.manager, w, http.StatusInternalServerError, "Failed to update API key")
		return
	}

	updatedDBKey, err := h.manager.GetAPIKeyInfo(r.Context(), keyOrHash)
	if err != nil {
		h.manager.logger("ERROR", fmt.Sprintf("[GO-APIKEYS.updateAPIKey] Error retrieving updated API key: %v", err))
		handleError(h.manager, w, http.StatusInternalServerError, "Failed to retrieve updated API key")
		return
	}

	handleResponse(h.manager, w, http.StatusOK, updatedDBKey)
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
	if !isSystemAdmin(h.manager, r) {
		handleError(h.manager, w, http.StatusUnauthorized, "Unauthorized: not a system admin")
		return
	}

	_, params, _ := getRequestData(r)
	keyOrHash := params["key_or_hash"]
	if keyOrHash == "" {
		handleError(h.manager, w, http.StatusBadRequest, "Missing API key or hash")
		return
	}

	err := h.manager.DeleteAPIKey(r.Context(), keyOrHash)
	if err != nil {
		if err == ErrAPIKeyNotFound {
			handleError(h.manager, w, http.StatusNotFound, "API key not found")
		} else {
			h.manager.logger("ERROR", fmt.Sprintf("[GO-APIKEYS.deleteAPIKey] Error deleting API key: %v", err))
			handleError(h.manager, w, http.StatusInternalServerError, "Failed to delete API key")
		}
		return
	}

	handleResponse(h.manager, w, http.StatusNoContent, nil)
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
	state := isSystemAdmin(h.manager, r)
	handleResponse(h.manager, w, http.StatusOK, map[string]bool{"isSystemAdmin": state})
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
		apikeyManager.logger("ERROR", "[GO-APIKEYS.RegisterCRUDRoutes] Unsupported router type")
		return
	}
	apikeyManager.logger("INFO", "[GO-APIKEYS.RegisterCRUDRoutes] CRUD routes registered")
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// GenerateAPIKey generates a new API key
func GenerateAPIKey() string {
	apiKey, err := gonanoid.New(APIKEY_RANDOMSTRING_LENGTH)
	if err != nil {
		panic(err)
	}
	return APIKEY_PREFIX + apiKey
}

// IsApiKey checks if the given string is a valid API key
func IsApiKey(key string) bool {
	correctLength := len(key) == (APIKEY_RANDOMSTRING_LENGTH + len(APIKEY_PREFIX))
	if !correctLength {
		return false
	}
	correctPrefix := key[:len(APIKEY_PREFIX)] == APIKEY_PREFIX
	return correctPrefix
}

// GenerateAPIKeyHash generates a hash and hint for the given API key
func GenerateAPIKeyHash(apiKey string) (hash string, hint string, err error) {
	if len(apiKey) < (APIKEY_RANDOMSTRING_LENGTH + len(APIKEY_PREFIX)) {
		return "", "", errors.New("bad API key")
	}
	hashBytes := sha3.Sum512([]byte(apiKey))
	hash = hex.EncodeToString(hashBytes[:])
	hint = apiKey[:3] + "..." + apiKey[len(apiKey)-3:]
	return hash, hint, nil
}
