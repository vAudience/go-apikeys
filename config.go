// github.com/vaudience/go-apikeys/config.go
package apikeys

import (
	"regexp"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/gofiber/fiber/v2"
)

type Config struct {
	HeaderKey       string
	RedisClient     redis.UniversalClient
	SystemAPIKey    string
	EnableCRUD      bool
	CRUDGroup       fiber.Router
	EnableRateLimit bool
	RateLimitRules  []RateLimitRule
}

type RateLimitRule struct {
	Path      string
	Timespan  time.Duration
	Limit     int
	ApplyTo   []string
	pathRegex *regexp.Regexp
}
