// github.com/vaudience/go-apikeys/middleware.go
package apikeys

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
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

type APIKeyManager struct {
	config  *Config
	logger  LogAdapter
	repo    *RedisRepository
	limiter *RateLimiter
}

func (m *APIKeyManager) UserID(c *fiber.Ctx) string {
	apiKeyCtx, ok := c.Locals(LOCALS_KEY_APIKEYS).(*APIKeyInfo)
	if !ok {
		return ""
	}
	return apiKeyCtx.UserID
}

func (m *APIKeyManager) APIKey(c *fiber.Ctx) string {
	apiKeyCtx, ok := c.Locals(LOCALS_KEY_APIKEYS).(*APIKeyInfo)
	if !ok {
		return ""
	}
	return apiKeyCtx.APIKeyHash
}

func (m *APIKeyManager) OrgID(c *fiber.Ctx) string {
	apiKeyCtx, ok := c.Locals(LOCALS_KEY_APIKEYS).(*APIKeyInfo)
	if !ok {
		return ""
	}
	return apiKeyCtx.OrgID
}

func (m *APIKeyManager) Name(c *fiber.Ctx) string {
	apiKeyCtx, ok := c.Locals(LOCALS_KEY_APIKEYS).(*APIKeyInfo)
	if !ok {
		return ""
	}
	return apiKeyCtx.Name
}

func (m *APIKeyManager) Email(c *fiber.Ctx) string {
	apiKeyCtx, ok := c.Locals(LOCALS_KEY_APIKEYS).(*APIKeyInfo)
	if !ok {
		return ""
	}
	return apiKeyCtx.Email
}

func (m *APIKeyManager) Metadata(c *fiber.Ctx) map[string]any {
	apiKeyCtx, ok := c.Locals(LOCALS_KEY_APIKEYS).(*APIKeyInfo)
	if !ok {
		return nil
	}
	return apiKeyCtx.Metadata
}

func (m *APIKeyManager) Get(c *fiber.Ctx) *APIKeyInfo {
	if c.Locals(LOCALS_KEY_APIKEYS) == nil {
		return nil
	}
	apiKeyCtx, ok := c.Locals(LOCALS_KEY_APIKEYS).(*APIKeyInfo)
	if !ok {
		m.logger("ERROR", fmt.Sprintf("API key information not found in locals: %v", c.Locals(LOCALS_KEY_APIKEYS)))
		return nil
	}
	if apiKeyCtx == nil {
		m.logger("WARN", "API key information is nil")
		return nil
	}
	return apiKeyCtx
}

func New(config *Config) (*APIKeyManager, error) {
	logger := emptyLogger
	if config.Logger != nil {
		logger = config.Logger
	}

	repo, err := NewRedisRepository(config.RedisClient)
	if err != nil {
		logger("FATAL", fmt.Sprintf("Failed to create a new Redis repository: %v", err))
		return nil, err
	}

	var limiter *RateLimiter
	if config.EnableRateLimit {
		limiter = NewRateLimiter(config.RedisClient, config.RateLimitRules)
	}

	manager := &APIKeyManager{
		config:  config,
		logger:  logger,
		repo:    repo,
		limiter: limiter,
	}

	if config.EnableCRUD {
		RegisterCRUDRoutes(config.CRUDGroup, manager)
	}

	return manager, nil
}

func (m *APIKeyManager) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		for _, pattern := range m.config.IgnoreApiKeyForRoutePatterns {
			ok, _ := regexp.MatchString(pattern, c.Path())
			if ok {
				m.logger("DEBUG", fmt.Sprintf("Ignoring API key for route: (%s)", c.Path()))
				return c.Next()
			}
		}
		apiKey := c.Get(m.config.HeaderKey)
		apiKeyInfo, err := m.repo.GetAPIKeyInfo(apiKey)
		if err != nil {
			if err == redis.Nil {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": ErrInvalidAPIKey.Error(),
				})
			}
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": ErrFailedToRetrieveAPIKeyInfo.Error(),
			})
		}

		if m.config.EnableRateLimit {
			allowed, err := m.limiter.Allow(c, m)
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

		c.Locals(LOCALS_KEY_APIKEYS, apiKeyInfo)
		// log.Printf("API key information: %v\n", apiKeyInfo)
		return c.Next()
	}
}

func (m *APIKeyManager) Config() *Config {
	return m.config
}

func (m *APIKeyManager) Logger() LogAdapter {
	return m.logger
}

func (m *APIKeyManager) Repository() *RedisRepository {
	return m.repo
}

func (m *APIKeyManager) RateLimiter() *RateLimiter {
	return m.limiter
}

func (m *APIKeyManager) SetLogger(logger LogAdapter) {
	m.logger = logger
}
