// github.com/vaudience/go-apikeys/crud.go
package apikeys

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/gofiber/fiber/v2"
	gonanoid "github.com/matoous/go-nanoid/v2"
	"golang.org/x/crypto/sha3"
)

var (
	ErrUnauthorized            = errors.New("unauthorized")
	ErrInvalidJSON             = errors.New("invalid JSON")
	APIKEY_RANDOMSTRING_LENGTH = 32
	APIKEY_PREFIX              = "gak_"
)

const (
	METADATA_KEYS_SYSTEM_ADMIN = "systemadmin"
)

func RegisterCRUDRoutes(group fiber.Router, apikeyManager *APIKeyManager) {
	group.Post("/apikeys", createAPIKey(apikeyManager))
	group.Get("/apikeys/search", searchAPIKeys(apikeyManager))
	group.Get("/apikeys/issystemadmin", isSystemAdminHandler(apikeyManager))
	group.Get("/apikeys/:id", getAPIKey(apikeyManager))
	group.Put("/apikeys/:id", updateAPIKey(apikeyManager))
	group.Delete("/apikeys/:id", deleteAPIKey(apikeyManager))
	apikeyManager.logger("INFO", "[GO-APIKEYS.RegisterCRUDRoutes] CRUD routes registered")
}

func isSystemAdmin(c *fiber.Ctx, apikeyManager *APIKeyManager) bool {
	apiKeyCtx := apikeyManager.Get(c)
	if apiKeyCtx == nil {
		// log.Println("API key not found in context")
		apikeyManager.logger("INFO", "NO ApiKeyInfo found in request context")
		return false
	}
	apikeyManager.logger("INFO", fmt.Sprintf("[GO-APIKEYS.isSystemAdmin] API key context: %v\n", apiKeyCtx))
	// content := fmt.Sprintf("MetaData: %v", apiKeyCtx.Metadata)
	// apikeyManager.logger("INFO", content)
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
//
//	@Id				searchAPIKeys
//	@Summary		Search API keys
//	@Description	Search for API keys based on a query string
//	@Tags			APIKeys
//	@Accept			json
//	@Produce		json
//	@Param			query	query		string	true	"Query string to search API keys"
//	@Success		200		{array}		APIKeyInfo
//	@Failure		401		{object}	ApiError
//	@Failure		500		{object}	ApiError
//	@Router			/apikeys/search [get]
//	@Security		ApiKey
func searchAPIKeys(apikeyManager *APIKeyManager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !isSystemAdmin(c, apikeyManager) {
			apiKeyCtx := apikeyManager.Get(c)
			apikeyManager.logger("INFO", fmt.Sprintf("[GO-APIKEYS.searchAPIKeys] Unauthorized: not a system admin:%v\n", apiKeyCtx))
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": ErrUnauthorized.Error(),
			})
		}
		query := c.Query("query")
		if query == "" {
			query = "*"
		}
		apikeyManager.logger("INFO", fmt.Sprintf("[GO-APIKEYS.searchAPIKeys] Searching for API keys with query: (%s)", query))
		apiKeyInfos, err := apikeyManager.repo.SearchAPIKeys(query, apikeyManager.logger)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.JSON(apiKeyInfos)
	}
}

// createAPIKey godoc
//
//	@Id				createAPIKey
//	@Summary		Create a new API key
//	@Description	Create a new API key
//	@Tags			APIKeys
//	@Accept			json
//	@Produce		json
//	@Param			apiKeyInfo	body		APIKeyInfo	true	"API key information"
//	@Success		201			{object}	APIKeyInfo
//	@Failure		400			{object}	ApiError
//	@Failure		401			{object}	ApiError
//	@Failure		500			{object}	ApiError
//	@Router			/apikeys [post]
//	@Security		ApiKey
func createAPIKey(apikeyManager *APIKeyManager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !isSystemAdmin(c, apikeyManager) {
			apikeyManager.logger("INFO", "Unauthorized: not a system admin")
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": ErrUnauthorized.Error(),
			})
		}

		var apiKeyInfo APIKeyInfo
		if err := c.BodyParser(&apiKeyInfo); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": ErrInvalidJSON.Error(),
			})
		}

		apiKey := GenerateAPIKey()
		hash, hint, err := GenerateAPIKeyHash(apiKey)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		apiKeyInfo.APIKeyHash = hash
		apiKeyInfo.APIKeyHint = hint
		err = apikeyManager.repo.SetAPIKeyInfo(&apiKeyInfo)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		// do not store the clear API key in the database, but return it to the caller (once)
		apiKeyInfo.APIKey = apiKey
		callerInfo := apiKeyInfo.Filter(true, false)
		return c.JSON(callerInfo)
	}
}

// getAPIKey godoc
//
//	@Id				getAPIKey
//	@Summary		Get an API key
//	@Description	Retrieve an API key by its ID
//	@Tags			APIKeys
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string	true	"API key ID"
//	@Success		200		{object}	APIKeyInfo
//	@Failure		401		{object}	ApiError
//	@Failure		404		{object}	ApiError
//	@Failure		500		{object}	ApiError
//	@Router			/apikeys/{id} [get]
//	@Security		ApiKey
func getAPIKey(apikeyManager *APIKeyManager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !isSystemAdmin(c, apikeyManager) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": ErrUnauthorized.Error(),
			})
		}

		apiKey := c.Params("id")
		apiKeyInfo, err := apikeyManager.repo.GetAPIKeyInfo(apiKey)
		if err != nil {
			if err == ErrAPIKeyNotFound {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"error": err.Error(),
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.JSON(apiKeyInfo)
	}
}

// updateAPIKey godoc
//
//	@Id				updateAPIKey
//	@Summary		Update an existing API key
//	@Description	Update an existing API key with new information
//	@Tags			APIKeys
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string		true	"API key ID"
//	@Param			apiKeyInfo	body		APIKeyInfo	true	"Updated API key information"
//	@Success		200			{object}	APIKeyInfo
//	@Failure		400			{object}	ApiError
//	@Failure		401			{object}	ApiError
//	@Failure		404			{object}	ApiError
//	@Failure		500			{object}	ApiError
//	@Router			/apikeys/{id} [put]
//	@Security		ApiKey
func updateAPIKey(apikeyManager *APIKeyManager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !isSystemAdmin(c, apikeyManager) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": ErrUnauthorized.Error(),
			})
		}

		var apiKeyInfo APIKeyInfo
		if err := c.BodyParser(&apiKeyInfo); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": ErrInvalidJSON.Error(),
			})
		}

		err := apikeyManager.repo.SetAPIKeyInfo(&apiKeyInfo)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.JSON(apiKeyInfo)
	}
}

// deleteAPIKey godoc
//
//	@Id				deleteAPIKey
//	@Summary		Delete an API key
//	@Description	Delete an API key by its ID
//	@Tags			APIKeys
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string	true	"API key ID"
//	@Success		204		"API key deleted successfully"
//	@Failure		401		{object}	ApiError
//	@Failure		500		{object}	ApiError
//	@Router			/apikeys/{id} [delete]
//	@Security		ApiKey
func deleteAPIKey(apikeyManager *APIKeyManager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !isSystemAdmin(c, apikeyManager) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": ErrUnauthorized.Error(),
			})
		}

		apiKey := c.Params("id")
		err := apikeyManager.repo.DeleteAPIKeyInfo(apiKey)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.SendStatus(fiber.StatusNoContent)
	}
}

// isSystemAdminHandler godoc
//
//	@Id				isSystemAdminHandler
//	@Summary		Check if the API key belongs to a system admin
//	@Description	Determine if the API key in the request context has system admin privileges
//	@Tags			APIKeys
//	@Accept			json
//	@Produce		json
//	@Success		200		{object}	map[string]bool
//	@Failure		401		{object}	ApiError
//	@Router			/apikeys/issystemadmin [get]
//	@Security		ApiKey
func isSystemAdminHandler(apikeyManager *APIKeyManager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		state := isSystemAdmin(c, apikeyManager)
		return c.JSON(fiber.Map{
			"isSystemAdmin": state,
		})
	}
}

func GenerateAPIKey() string {
	apiKey, err := gonanoid.New(APIKEY_RANDOMSTRING_LENGTH)
	if err != nil {
		panic(err)
	}
	return APIKEY_PREFIX + apiKey
}

func GenerateAPIKeyHash(apiKey string) (hash string, hint string, err error) {
	if len(apiKey) < (APIKEY_RANDOMSTRING_LENGTH + len(APIKEY_PREFIX)) {
		return "", "", errors.New("bad API key")
	}
	// Generate a sha3-512 hash of the API key
	hashBytes := sha3.Sum512([]byte(apiKey))
	// turn into string
	hash = hex.EncodeToString(hashBytes[:])
	// Generate a hint for the API key
	// first 3 and last 3 characters of the API key
	hint = apiKey[:3] + "..." + apiKey[len(apiKey)-3:]
	// Convert the byte slice to a string and return
	return hash, hint, nil
}
