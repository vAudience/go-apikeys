// github.com/vaudience/go-apikeys/ratelimit.go
package apikeys

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
)

const (
	RATELIMITER_REDIS_KEY_RATELIMIT_PREFIX = "go-apikeys-ratelimiter"
	RATELIMITER_REDIS_KEY_SEPARATOR        = ":"
)

type RateLimitRuleTarget string

const (
	RateLimitRuleTargetAPIKey RateLimitRuleTarget = "apikey"
	RateLimitRuleTargetUserID RateLimitRuleTarget = "userID"
	RateLimitRuleTargetOrgID  RateLimitRuleTarget = "orgID"
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

func (r *RateLimiter) Allow(c *fiber.Ctx, apikeyManager *APIKeyManager) (bool, error) {
	apiKeyCtx := apikeyManager.Get(c)
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
			case RateLimitRuleTargetAPIKey:
				key = apiKeyCtx.APIKeyHash
			case RateLimitRuleTargetUserID:
				key = apiKeyCtx.UserID
			case RateLimitRuleTargetOrgID:
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

	tx.ZRemRangeByScore(context.Background(), redisKey, "0", strconv.FormatInt(now-int64(timespan), 10))
	tx.ZAdd(context.Background(), redisKey, redis.Z{Score: float64(now), Member: strconv.FormatInt(now, 10)})
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

func (r *RateLimiter) GetCurrentValueByAPIKeyInfo(apiKeyInfo *APIKeyInfo, rulePath string) (int64, error) {
	for _, rule := range r.rules {
		if rule.Path != rulePath {
			continue
		}

		var values []int64

		for _, applyTo := range rule.ApplyTo {
			var key string
			switch applyTo {
			case RateLimitRuleTargetAPIKey:
				key = apiKeyInfo.APIKeyHash
			case RateLimitRuleTargetUserID:
				key = apiKeyInfo.UserID
			case RateLimitRuleTargetOrgID:
				key = apiKeyInfo.OrgID
			default:
				continue
			}

			value, err := r.getCurrentValue(key, rule.Timespan)
			if err != nil {
				return 0, err
			}
			values = append(values, value)
		}

		if len(values) > 0 {
			return values[0], nil
		}
	}

	return 0, nil
}

func (r *RateLimiter) GetCurrentValueByContext(c *fiber.Ctx, rulePath string, apikeyManager *APIKeyManager) (int64, error) {
	apiKeyInfo := apikeyManager.Get(c)
	if apiKeyInfo == nil {
		return 0, nil
	}
	return r.GetCurrentValueByAPIKeyInfo(apiKeyInfo, rulePath)
}

func (r *RateLimiter) getCurrentValue(key string, timespan time.Duration) (int64, error) {
	now := time.Now().UnixNano()
	redisKey := assembleRateLimitKey(key)

	count, err := r.client.ZCount(context.Background(), redisKey, strconv.FormatInt(now-int64(timespan), 10), "+inf").Result()
	if err != nil {
		return 0, err
	}

	return count, nil
}

func assembleRateLimitKey(key string) string {
	return strings.Join([]string{RATELIMITER_REDIS_KEY_RATELIMIT_PREFIX, key}, RATELIMITER_REDIS_KEY_SEPARATOR)
}
