// github.com/vaudience/go-apikeys/crud.go
package apikeys

import (
	"encoding/hex"
	"errors"
	"log"

	"github.com/gofiber/fiber/v2"
	gonanoid "github.com/matoous/go-nanoid/v2"
	"golang.org/x/crypto/sha3"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrInvalidJSON  = errors.New("invalid JSON")
)

const (
	METADATA_KEYS_SYSTEM_ADMIN = "systemadmin"
	APIKEY_PREFIX              = "gak_"
)

func RegisterCRUDRoutes(group fiber.Router, apikeyManager *APIKeyManager) {
	group.Post("/apikeys", createAPIKey(apikeyManager))
	group.Get("/apikeys/:id", getAPIKey(apikeyManager))
	group.Put("/apikeys/:id", updateAPIKey(apikeyManager))
	group.Delete("/apikeys/:id", deleteAPIKey(apikeyManager))
}

func isSystemAdmin(c *fiber.Ctx, apikeyManager *APIKeyManager) bool {
	apiKeyCtx := apikeyManager.Get(c)
	if apiKeyCtx == nil {
		// log.Println("API key not found in context")
		return false
	}
	log.Printf("API key context: %v\n", apiKeyCtx)
	systemAdmin, ok := apiKeyCtx.Metadata[METADATA_KEYS_SYSTEM_ADMIN]
	if !ok {
		// log.Printf("API key [METADATA_KEYS_SYSTEM_ADMIN] not found in context:%v\n", apiKeyCtx)
		return false
	}
	isSysAdmin, ok := systemAdmin.(bool)
	if !ok {
		// log.Printf("API key is not a boolean:%v\n", systemAdmin)
		return false
	}
	return isSysAdmin
}

func createAPIKey(apikeyManager *APIKeyManager) fiber.Handler {
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

func GenerateAPIKey() string {
	apiKey, err := gonanoid.New(24)
	if err != nil {
		panic(err)
	}
	return APIKEY_PREFIX + apiKey
}

func GenerateAPIKeyHash(apiKey string) (hash string, hint string, err error) {
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
