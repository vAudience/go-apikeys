// github.com/vaudience/go-apikeys/config.go
package apikeys

import (
	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
)

type Config struct {
	HeaderKey                    string
	IgnoreApiKeyForRoutePatterns []string
	RedisClient                  redis.UniversalClient
	SystemAPIKey                 string
	EnableCRUD                   bool
	CRUDGroup                    fiber.Router
	EnableRateLimit              bool
	RateLimitRules               []RateLimitRule
	Logger                       LogAdapter
}
