// github.com/vaudience/go-apikeys/crud.go
package apikeys

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	gonanoid "github.com/matoous/go-nanoid/v2"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrInvalidJSON  = errors.New("invalid JSON")
)

const (
	METADATA_KEYS_SYSTEM_ADMIN = "systemadmin"
	APIKEY_PREFIX              = "gak_"
)

func RegisterCRUDRoutes(group fiber.Router, repo Repository) {
	group.Post("/", createAPIKey(repo))
	group.Get("/:id", getAPIKey(repo))
	group.Put("/:id", updateAPIKey(repo))
	group.Delete("/:id", deleteAPIKey(repo))
}

func isSystemAdmin(c *fiber.Ctx) bool {
	apiKeyCtx := Get(c)
	if apiKeyCtx == nil {
		return false
	}
	systemAdmin, ok := apiKeyCtx.Metadata[METADATA_KEYS_SYSTEM_ADMIN]
	return ok && systemAdmin.(bool)
}

func createAPIKey(repo Repository) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !isSystemAdmin(c) {
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
		err := repo.SaveAPIKeyInfo(apiKey, &apiKeyInfo)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.JSON(fiber.Map{
			"api_key": apiKey,
		})
	}
}

func getAPIKey(repo Repository) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !isSystemAdmin(c) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": ErrUnauthorized.Error(),
			})
		}

		apiKey := c.Params("id")
		apiKeyInfo, err := repo.GetAPIKeyInfo(apiKey)
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

func updateAPIKey(repo Repository) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !isSystemAdmin(c) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": ErrUnauthorized.Error(),
			})
		}

		apiKey := c.Params("id")
		var apiKeyInfo APIKeyInfo
		if err := c.BodyParser(&apiKeyInfo); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": ErrInvalidJSON.Error(),
			})
		}

		err := repo.SaveAPIKeyInfo(apiKey, &apiKeyInfo)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.JSON(apiKeyInfo)
	}
}

func deleteAPIKey(repo Repository) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !isSystemAdmin(c) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": ErrUnauthorized.Error(),
			})
		}

		apiKey := c.Params("id")
		err := repo.DeleteAPIKeyInfo(apiKey)
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
