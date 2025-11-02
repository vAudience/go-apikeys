package apikeys

import (
	"context"
	"net/http"
	"regexp"

	"github.com/gofiber/fiber/v2"
)

func (m *APIKeyManager) fiberMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		for _, pattern := range m.config.IgnoreApiKeyForRoutePatterns {
			if ok, _ := regexp.MatchString(pattern, c.Path()); ok {
				return c.Next()
			}
		}

		apiKey := c.Get(m.config.HeaderKey)
		apiKeyInfo, err := m.GetAPIKeyInfo(c.Context(), apiKey)
		if err != nil {
			// Return generic unauthorized message for all auth failures
			// to prevent information leakage (timing attacks, key enumeration)
			return c.Status(fiber.StatusUnauthorized).SendString(ErrUnauthorized.Error())
		}

		if m.config.EnableRateLimit {
			allowed, err := m.limiter.Allow(c.Context(), m.framework, c)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).SendString(ErrFailedToCheckRateLimit.Error())
			}
			if !allowed {
				return c.Status(fiber.StatusTooManyRequests).SendString(ErrRateLimitExceeded.Error())
			}
		}

		c.Locals(LOCALS_KEY_APIKEYS, apiKeyInfo)
		return c.Next()
	}
}

func (m *APIKeyManager) standardMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, pattern := range m.config.IgnoreApiKeyForRoutePatterns {
				if ok, _ := regexp.MatchString(pattern, r.URL.Path); ok {
					next.ServeHTTP(w, r)
					return
				}
			}

			apiKey := r.Header.Get(m.config.HeaderKey)
			apiKeyInfo, err := m.GetAPIKeyInfo(r.Context(), apiKey)
			if err != nil {
				// Return generic unauthorized message for all auth failures
				// to prevent information leakage (timing attacks, key enumeration)
				http.Error(w, ErrUnauthorized.Error(), http.StatusUnauthorized)
				return
			}

			if m.config.EnableRateLimit {
				allowed, err := m.limiter.Allow(r.Context(), m.framework, r)
				if err != nil {
					http.Error(w, ErrFailedToCheckRateLimit.Error(), http.StatusInternalServerError)
					return
				}
				if !allowed {
					http.Error(w, ErrRateLimitExceeded.Error(), http.StatusTooManyRequests)
					return
				}
			}

			// Use typed context key for stdlib to prevent collisions
			ctx := context.WithValue(r.Context(), contextKeyAPIKeyInfo, apiKeyInfo)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}
