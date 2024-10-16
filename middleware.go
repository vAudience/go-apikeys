package apikeys

import (
	"context"
	"net/http"
	"regexp"

	"github.com/gofiber/fiber/v2"
)

func (m *APIKeyManager) Middleware() interface{} {
	switch m.framework.(type) {
	case *FiberFramework:
		return m.fiberMiddleware()
	default:
		return m.standardMiddleware()
	}
}

func (m *APIKeyManager) fiberMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// m.logger("DEBUG", fmt.Sprintf("Fiber Middleware called for path: %s", c.Path()))

		for _, pattern := range m.config.IgnoreApiKeyForRoutePatterns {
			if ok, _ := regexp.MatchString(pattern, c.Path()); ok {
				// m.logger("DEBUG", fmt.Sprintf("Ignoring API key for route: (%s)", c.Path()))
				return c.Next()
			}
		}

		apiKey := c.Get(m.config.HeaderKey)
		apiKeyInfo, err := m.GetAPIKeyInfo(c.Context(), apiKey)
		if err != nil {
			if err == ErrAPIKeyNotFound {
				return c.Status(fiber.StatusUnauthorized).SendString(ErrInvalidAPIKey.Error())
			}
			return c.Status(fiber.StatusUnauthorized).SendString(ErrFailedToRetrieveAPIKeyInfo.Error())
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

		// m.logger("DEBUG", "Fiber Middleware completed successfully")
		return c.Next()
	}
}

func (m *APIKeyManager) standardMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// m.logger("DEBUG", fmt.Sprintf("Standard Middleware called for path: %s", r.URL.Path))

			for _, pattern := range m.config.IgnoreApiKeyForRoutePatterns {
				if ok, _ := regexp.MatchString(pattern, r.URL.Path); ok {
					// m.logger("DEBUG", fmt.Sprintf("Ignoring API key for route: (%s)", r.URL.Path))
					next.ServeHTTP(w, r)
					return
				}
			}

			apiKey := r.Header.Get(m.config.HeaderKey)
			apiKeyInfo, err := m.GetAPIKeyInfo(r.Context(), apiKey)
			if err != nil {
				if err == ErrAPIKeyNotFound {
					http.Error(w, ErrInvalidAPIKey.Error(), http.StatusUnauthorized)
					return
				}
				http.Error(w, ErrFailedToRetrieveAPIKeyInfo.Error(), http.StatusUnauthorized)
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

			ctx := context.WithValue(r.Context(), LOCALS_KEY_APIKEYS, apiKeyInfo)
			r = r.WithContext(ctx)

			// m.logger("DEBUG", "Standard Middleware completed successfully")
			next.ServeHTTP(w, r)
		})
	}
}
