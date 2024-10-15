package apikeys

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/gofiber/fiber/v2"
	gonanoid "github.com/matoous/go-nanoid/v2"
	"github.com/valyala/fasthttp/fasthttpadaptor"
	"golang.org/x/crypto/sha3"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrInvalidJSON  = errors.New("invalid JSON")
)

func RegisterCRUDRoutes(router interface{}, apikeyManager *APIKeyManager) {
	switch r := router.(type) {
	case interface {
		Post(path string, handler interface{}) interface{}
		Get(path string, handler interface{}) interface{}
		Put(path string, handler interface{}) interface{}
		Delete(path string, handler interface{}) interface{}
	}:
		r.Post("/apikeys", createAPIKey(apikeyManager))
		r.Get("/apikeys/search", searchAPIKeys(apikeyManager))
		r.Get("/apikeys/issystemadmin", isSystemAdminHandler(apikeyManager))
		r.Get("/apikeys/:key_or_hash", getAPIKey(apikeyManager))
		r.Put("/apikeys/:key_or_hash", updateAPIKey(apikeyManager))
		r.Delete("/apikeys/:key_or_hash", deleteAPIKey(apikeyManager))
	case fiber.Router:
		r.Post("/apikeys", wrapHandler(createAPIKey(apikeyManager)))
		r.Get("/apikeys/search", wrapHandler(searchAPIKeys(apikeyManager)))
		r.Get("/apikeys/issystemadmin", wrapHandler(isSystemAdminHandler(apikeyManager)))
		r.Get("/apikeys/:key_or_hash", wrapHandler(getAPIKey(apikeyManager)))
		r.Put("/apikeys/:key_or_hash", wrapHandler(updateAPIKey(apikeyManager)))
		r.Delete("/apikeys/:key_or_hash", wrapHandler(deleteAPIKey(apikeyManager)))
	default:
		apikeyManager.logger("ERROR", "[GO-APIKEYS.RegisterCRUDRoutes] Unsupported router type")
		return
	}
	apikeyManager.logger("INFO", "[GO-APIKEYS.RegisterCRUDRoutes] CRUD routes registered")
}

// wrapHandler converts various handler types to a fiber.Handler
func wrapHandler(handler interface{}) fiber.Handler {
	switch h := handler.(type) {
	case func(*fiber.Ctx) error:
		return h
	case func(http.ResponseWriter, *http.Request):
		return func(c *fiber.Ctx) error {
			handler := fasthttpadaptor.NewFastHTTPHandlerFunc(h)
			handler(c.Context())
			return nil
		}
	case http.HandlerFunc:
		return func(c *fiber.Ctx) error {
			handler := fasthttpadaptor.NewFastHTTPHandlerFunc(h)
			handler(c.Context())
			return nil
		}
	default:
		return func(c *fiber.Ctx) error {
			return fiber.ErrInternalServerError
		}
	}
}

func isSystemAdmin(req interface{}, apikeyManager *APIKeyManager) bool {
	apiKeyCtx := apikeyManager.Get(req)
	if apiKeyCtx == nil {
		apikeyManager.logger("INFO", "NO ApiKeyInfo found in request context")
		return false
	}
	systemAdmin, ok := apiKeyCtx.Metadata[METADATA_KEYS_SYSTEM_ADMIN]
	if !ok {
		apikeyManager.logger("INFO", fmt.Sprintf("[GO-APIKEYS.isSystemAdmin] API key [METADATA_KEYS_SYSTEM_ADMIN] not found in context:%v\n", apiKeyCtx))
		return false
	}
	isSysAdmin, ok := systemAdmin.(bool)
	if !ok {
		apikeyManager.logger("INFO", fmt.Sprintf("[GO-APIKEYS.isSystemAdmin] API key systemAdmin metadata is not a boolean:(%v)\n", systemAdmin))
		return false
	}
	return isSysAdmin
}

// searchAPIKeys godoc
// @Summary Search API keys
// @Description Search for API keys based on a query string
// @Tags APIKeys
// @Accept json
// @Produce json
// @Param query query string false "Query string to search API keys"
// @Success 200 {array} APIKeyInfo
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /apikeys/search [get]
// @Security ApiKey
func searchAPIKeys(apikeyManager *APIKeyManager) interface{} {
	return apikeyManager.framework.WrapMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if !isSystemAdmin(r, apikeyManager) {
			apiKeyCtx := apikeyManager.Get(r)
			apikeyManager.logger("INFO", fmt.Sprintf("[GO-APIKEYS.searchAPIKeys] Unauthorized: not a system admin:%v\n", apiKeyCtx))
			apikeyManager.framework.WriteResponse(w, http.StatusUnauthorized, []byte(ErrUnauthorized.Error()))
			return
		}
		query := apikeyManager.framework.GetRequestParam(r, "query")
		if query == "" {
			query = "*"
		}
		apikeyManager.logger("INFO", fmt.Sprintf("[GO-APIKEYS.searchAPIKeys] Searching for API keys with query: (%s)", query))
		apiKeyInfos, err := apikeyManager.SearchAPIKeys(r.Context(), query, 0, 1000)
		if err != nil {
			apikeyManager.framework.WriteResponse(w, http.StatusInternalServerError, []byte(err.Error()))
			return
		}

		response, _ := json.Marshal(apiKeyInfos)
		apikeyManager.framework.WriteResponse(w, http.StatusOK, response)
	})
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
func createAPIKey(apikeyManager *APIKeyManager) interface{} {
	return apikeyManager.framework.WrapMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if !isSystemAdmin(r, apikeyManager) {
			apikeyManager.logger("INFO", "Unauthorized: not a system admin")
			apikeyManager.framework.WriteResponse(w, http.StatusUnauthorized, []byte(ErrUnauthorized.Error()))
			return
		}

		var apiKeyInfo APIKeyInfo
		err := json.NewDecoder(r.Body).Decode(&apiKeyInfo)
		if err != nil {
			apikeyManager.framework.WriteResponse(w, http.StatusBadRequest, []byte(ErrInvalidJSON.Error()))
			return
		}

		err = apikeyManager.CreateAPIKey(r.Context(), &apiKeyInfo)
		if err != nil {
			apikeyManager.logger("ERROR", fmt.Sprintf("[GO-APIKEYS.createAPIKey] Error creating API key: %v", err))
			apikeyManager.framework.WriteResponse(w, http.StatusInternalServerError, []byte(err.Error()))
			return
		}

		callerInfo := apiKeyInfo.Filter(true, false)
		apikeyManager.logger("INFO", fmt.Sprintf("[GO-APIKEYS.createAPIKey] API key(%s) created: %v\n", apiKeyInfo.APIKey, callerInfo))
		response, _ := json.Marshal(callerInfo)
		apikeyManager.framework.WriteResponse(w, http.StatusCreated, response)
	})
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
func getAPIKey(apikeyManager *APIKeyManager) interface{} {
	return apikeyManager.framework.WrapMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if !isSystemAdmin(r, apikeyManager) {
			apikeyManager.framework.WriteResponse(w, http.StatusUnauthorized, []byte(ErrUnauthorized.Error()))
			return
		}

		keyOrHash := apikeyManager.framework.GetRequestParam(r, "key_or_hash")
		if keyOrHash == "" {
			apikeyManager.framework.WriteResponse(w, http.StatusBadRequest, []byte("missing API key or hash"))
			return
		}

		apiKeyInfo, err := apikeyManager.GetAPIKeyInfo(r.Context(), keyOrHash)
		if err != nil {
			if err == ErrAPIKeyNotFound {
				apikeyManager.framework.WriteResponse(w, http.StatusNotFound, []byte(err.Error()))
				return
			}
			apikeyManager.framework.WriteResponse(w, http.StatusInternalServerError, []byte(err.Error()))
			return
		}

		response, _ := json.Marshal(apiKeyInfo)
		apikeyManager.framework.WriteResponse(w, http.StatusOK, response)
	})
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
func updateAPIKey(apikeyManager *APIKeyManager) interface{} {
	return apikeyManager.framework.WrapMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if !isSystemAdmin(r, apikeyManager) {
			apikeyManager.framework.WriteResponse(w, http.StatusUnauthorized, []byte(ErrUnauthorized.Error()))
			return
		}

		hash := apikeyManager.framework.GetRequestParam(r, "key_or_hash")
		if hash == "" {
			apikeyManager.framework.WriteResponse(w, http.StatusBadRequest, []byte("missing API key hash"))
			return
		}

		var apiKeyInfo APIKeyInfo
		err := json.NewDecoder(r.Body).Decode(&apiKeyInfo)
		if err != nil {
			apikeyManager.framework.WriteResponse(w, http.StatusBadRequest, []byte(ErrInvalidJSON.Error()))
			return
		}
		apiKeyInfo.APIKeyHash = hash

		err = apikeyManager.UpdateAPIKey(r.Context(), &apiKeyInfo)
		if err != nil {
			apikeyManager.framework.WriteResponse(w, http.StatusInternalServerError, []byte(err.Error()))
			return
		}

		updatedDBKey, err := apikeyManager.GetAPIKeyInfo(r.Context(), hash)
		if err != nil {
			apikeyManager.framework.WriteResponse(w, http.StatusInternalServerError, []byte(err.Error()))
			return
		}

		response, _ := json.Marshal(updatedDBKey)
		apikeyManager.framework.WriteResponse(w, http.StatusOK, response)
	})
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
func deleteAPIKey(apikeyManager *APIKeyManager) interface{} {
	return apikeyManager.framework.WrapMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if !isSystemAdmin(r, apikeyManager) {
			apikeyManager.framework.WriteResponse(w, http.StatusUnauthorized, []byte(ErrUnauthorized.Error()))
			return
		}

		keyOrHash := apikeyManager.framework.GetRequestParam(r, "key_or_hash")
		err := apikeyManager.DeleteAPIKey(r.Context(), keyOrHash)
		if err != nil {
			if err == ErrAPIKeyNotFound {
				apikeyManager.framework.WriteResponse(w, http.StatusNotFound, []byte("API key not found"))
				return
			}
			apikeyManager.framework.WriteResponse(w, http.StatusInternalServerError, []byte(err.Error()))
			return
		}

		apikeyManager.framework.WriteResponse(w, http.StatusNoContent, nil)
	})
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
func isSystemAdminHandler(apikeyManager *APIKeyManager) interface{} {
	return apikeyManager.framework.WrapMiddleware(func(w http.ResponseWriter, r *http.Request) {
		state := isSystemAdmin(r, apikeyManager)
		response, _ := json.Marshal(map[string]bool{"isSystemAdmin": state})
		apikeyManager.framework.WriteResponse(w, http.StatusOK, response)
	})
}

func GenerateAPIKey() string {
	apiKey, err := gonanoid.New(APIKEY_RANDOMSTRING_LENGTH)
	if err != nil {
		panic(err)
	}
	return APIKEY_PREFIX + apiKey
}

func IsApiKey(key string) bool {
	correctLength := len(key) == (APIKEY_RANDOMSTRING_LENGTH + len(APIKEY_PREFIX))
	if !correctLength {
		return false
	}
	correctPrefix := key[:len(APIKEY_PREFIX)] == APIKEY_PREFIX
	return correctPrefix
}

func GenerateAPIKeyHash(apiKey string) (hash string, hint string, err error) {
	if len(apiKey) < (APIKEY_RANDOMSTRING_LENGTH + len(APIKEY_PREFIX)) {
		return "", "", errors.New("bad API key")
	}
	hashBytes := sha3.Sum512([]byte(apiKey))
	hash = hex.EncodeToString(hashBytes[:])
	hint = apiKey[:3] + "..." + apiKey[len(apiKey)-3:]
	return hash, hint, nil
}
