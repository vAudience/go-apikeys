// github.com/vaudience/go-apikeys/middleware.go
package apikeys

import (
	"errors"

	"github.com/go-redis/redis/v8"
	"github.com/gofiber/fiber/v2"
)

const (
	LOCALS_KEY_APIKEYS                    = "apikey"
	ERROR_INVALID_API_KEY                 = "invalid API key"
	ERROR_FAILED_TO_RETRIEVE_API_KEY_INFO = "failed to retrieve API key information"
	ERROR_FAILED_TO_CHECK_RATE_LIMIT      = "failed to check rate limit"
	ERROR_RATE_LIMIT_EXCEEDED             = "rate limit exceeded"
)

var (
	ErrInvalidAPIKey              = errors.New(ERROR_INVALID_API_KEY)
	ErrFailedToRetrieveAPIKeyInfo = errors.New(ERROR_FAILED_TO_RETRIEVE_API_KEY_INFO)
	ErrFailedToCheckRateLimit     = errors.New(ERROR_FAILED_TO_CHECK_RATE_LIMIT)
	ErrRateLimitExceeded          = errors.New(ERROR_RATE_LIMIT_EXCEEDED)
)

type APIKeyContext struct {
	APIKey   string
	UserID   string
	OrgID    string
	Name     string
	Email    string
	Metadata map[string]any
}

func UserID(c *fiber.Ctx) string {
	apiKeyCtx, ok := c.Locals(LOCALS_KEY_APIKEYS).(*APIKeyContext)
	if !ok {
		return ""
	}
	return apiKeyCtx.UserID
}

func APIKey(c *fiber.Ctx) string {
	apiKeyCtx, ok := c.Locals(LOCALS_KEY_APIKEYS).(*APIKeyContext)
	if !ok {
		return ""
	}
	return apiKeyCtx.APIKey
}

func OrgID(c *fiber.Ctx) string {
	apiKeyCtx, ok := c.Locals(LOCALS_KEY_APIKEYS).(*APIKeyContext)
	if !ok {
		return ""
	}
	return apiKeyCtx.OrgID
}

func Name(c *fiber.Ctx) string {
	apiKeyCtx, ok := c.Locals(LOCALS_KEY_APIKEYS).(*APIKeyContext)
	if !ok {
		return ""
	}
	return apiKeyCtx.Name
}

func Email(c *fiber.Ctx) string {
	apiKeyCtx, ok := c.Locals(LOCALS_KEY_APIKEYS).(*APIKeyContext)
	if !ok {
		return ""
	}
	return apiKeyCtx.Email
}

func Metadata(c *fiber.Ctx) map[string]any {
	apiKeyCtx, ok := c.Locals(LOCALS_KEY_APIKEYS).(*APIKeyContext)
	if !ok {
		return nil
	}
	return apiKeyCtx.Metadata
}

func Get(c *fiber.Ctx) *APIKeyContext {
	apiKeyCtx, ok := c.Locals(LOCALS_KEY_APIKEYS).(*APIKeyContext)
	if !ok {
		return nil
	}
	return apiKeyCtx
}

func New(config *Config) fiber.Handler {
	repo := NewRedisRepository(config.RedisClient)
	var rateLimiter *RateLimiter
	if config.EnableRateLimit {
		rateLimiter = NewRateLimiter(config.RedisClient, config.RateLimitRules)
	}

	return func(c *fiber.Ctx) error {
		apiKey := c.Get(config.HeaderKey, config.SystemAPIKey)

		apiKeyInfo, err := repo.GetAPIKeyInfo(apiKey)
		if err != nil {
			if err == redis.Nil {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": ErrInvalidAPIKey.Error(),
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": ErrFailedToRetrieveAPIKeyInfo.Error(),
			})
		}

		if config.EnableRateLimit {
			allowed, err := rateLimiter.Allow(c)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": ErrFailedToCheckRateLimit.Error(),
				})
			}
			if !allowed {
				return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
					"error": ErrRateLimitExceeded.Error(),
				})
			}
		}

		apiKeyCtx := &APIKeyContext{
			APIKey:   apiKey,
			UserID:   apiKeyInfo.UserID,
			OrgID:    apiKeyInfo.OrgID,
			Name:     apiKeyInfo.Name,
			Email:    apiKeyInfo.Email,
			Metadata: apiKeyInfo.Metadata,
		}

		c.Locals(LOCALS_KEY_APIKEYS, apiKeyCtx)

		return c.Next()
	}
}
