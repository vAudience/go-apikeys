// github.com/vaudience/go-apikeys/ratelimit.go
package apikeys

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/gofiber/fiber/v2"
)

const (
	REDIS_KEY_RATELIMIT_PREFIX = "ratelimit"
	// REDIS_KEY_SEPARATOR        = ":"
)

type RateLimiter struct {
	client redis.UniversalClient
	rules  []RateLimitRule
}

func NewRateLimiter(client redis.UniversalClient, rules []RateLimitRule) *RateLimiter {
	for i := range rules {
		rules[i].pathRegex = regexp.MustCompile(rules[i].Path)
	}
	return &RateLimiter{
		client: client,
		rules:  rules,
	}
}

func (r *RateLimiter) Allow(c *fiber.Ctx) (bool, error) {
	apiKeyCtx := Get(c)
	if apiKeyCtx == nil {
		return false, nil
	}

	for _, rule := range r.rules {
		if !rule.pathRegex.MatchString(string(c.Request().URI().Path())) {
			continue
		}

		for _, applyTo := range rule.ApplyTo {
			var key string
			switch applyTo {
			case "apikey":
				key = apiKeyCtx.APIKey
			case "userID":
				key = apiKeyCtx.UserID
			case "orgID":
				key = apiKeyCtx.OrgID
			default:
				continue
			}

			allowed, err := r.checkRateLimit(key, rule.Timespan, rule.Limit)
			if err != nil {
				return false, err
			}
			if !allowed {
				return false, nil
			}
		}
	}

	return true, nil
}

func (r *RateLimiter) checkRateLimit(key string, timespan time.Duration, limit int) (bool, error) {
	now := time.Now().UnixNano()
	redisKey := assembleRateLimitKey(key)

	tx := r.client.TxPipeline()
	defer tx.Close()

	tx.ZRemRangeByScore(context.Background(), redisKey, "0", strconv.FormatInt(now-int64(timespan), 10))
	tx.ZAdd(context.Background(), redisKey, &redis.Z{Score: float64(now), Member: strconv.FormatInt(now, 10)})
	tx.Expire(context.Background(), redisKey, timespan)

	_, err := tx.Exec(context.Background())
	if err != nil {
		return false, err
	}

	count, err := r.client.ZCount(context.Background(), redisKey, "-inf", "+inf").Result()
	if err != nil {
		return false, err
	}

	return count <= int64(limit), nil
}

func assembleRateLimitKey(key string) string {
	return strings.Join([]string{REDIS_KEY_RATELIMIT_PREFIX, key}, REDIS_KEY_SEPARATOR)
}
