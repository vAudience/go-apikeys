// github.com/vaudience/go-apikeys/ratelimit.go
package apikeys

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/itsatony/go-datarepository"
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
	repo  datarepository.DataRepository
	rules []RateLimitRule
}

func NewRateLimiter(repo datarepository.DataRepository, rules []RateLimitRule) *RateLimiter {
	for i := range rules {
		rules[i].pathRegex = regexp.MustCompile(rules[i].Path)
	}
	return &RateLimiter{
		repo:  repo,
		rules: rules,
	}
}

func (r *RateLimiter) Allow(ctx context.Context, framework HTTPFramework, req interface{}) (bool, error) {
	for _, rule := range r.rules {
		if !rule.pathRegex.MatchString(framework.GetRequestPath(req)) {
			continue
		}

		for _, applyTo := range rule.ApplyTo {
			var key string
			switch applyTo {
			case RateLimitRuleTargetAPIKey:
				key = framework.GetContextValue(req, LOCALS_KEY_APIKEYS).(*APIKeyInfo).APIKeyHash
			case RateLimitRuleTargetUserID:
				key = framework.GetContextValue(req, LOCALS_KEY_APIKEYS).(*APIKeyInfo).UserID
			case RateLimitRuleTargetOrgID:
				key = framework.GetContextValue(req, LOCALS_KEY_APIKEYS).(*APIKeyInfo).OrgID
			default:
				continue
			}

			allowed, err := r.checkRateLimit(ctx, key, rule.Timespan, rule.Limit)
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

func (r *RateLimiter) checkRateLimit(ctx context.Context, key string, timespan time.Duration, limit int) (bool, error) {
	redisKey := assembleRateLimitKey(key)

	count, err := r.repo.AtomicIncrement(ctx, datarepository.SimpleIdentifier(redisKey))
	if err != nil {
		return false, fmt.Errorf("failed to increment rate limit counter: %w", err)
	}

	if count == 1 {
		// This is the first request, set the expiration
		err = r.repo.SetExpiration(ctx, datarepository.SimpleIdentifier(redisKey), timespan)
		if err != nil {
			return false, fmt.Errorf("failed to set expiration: %w", err)
		}
	}

	return count <= int64(limit), nil
}

func (r *RateLimiter) GetCurrentValueByAPIKeyInfo(ctx context.Context, apiKeyInfo *APIKeyInfo, rulePath string) (int64, error) {
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

			value, err := r.getCurrentValue(ctx, key)
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

// func (r *RateLimiter) GetCurrentValueByContext(c *fiber.Ctx, rulePath string, apikeyManager *APIKeyManager) (int64, error) {
// 	apiKeyInfo := apikeyManager.Get(c)
// 	if apiKeyInfo == nil {
// 		return 0, nil
// 	}
// 	return r.GetCurrentValueByAPIKeyInfo(apiKeyInfo, rulePath)
// }

func (r *RateLimiter) getCurrentValue(ctx context.Context, key string) (int64, error) {
	redisKey := assembleRateLimitKey(key)

	var count int64
	err := r.repo.Read(ctx, datarepository.SimpleIdentifier(redisKey), &count)
	if err != nil {
		if datarepository.IsNotFoundError(err) {
			return 0, nil
		}
		return 0, err
	}

	return count, nil
}

func assembleRateLimitKey(key string) string {
	return strings.Join([]string{RATELIMITER_REDIS_KEY_RATELIMIT_PREFIX, key}, RATELIMITER_REDIS_KEY_SEPARATOR)
}
