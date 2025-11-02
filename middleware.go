package apikeys

import (
	"context"
	"net/http"

	"github.com/gofiber/fiber/v2"
)

func (m *APIKeyManager) fiberMiddleware() fiber.Handler {
	// Compile patterns if needed (supports config changes after initialization)
	m.compileIgnorePatternsIfNeeded()

	return func(c *fiber.Ctx) error {
		// Check pre-compiled patterns (much faster than compiling on every request)
		path := c.Path()
		for _, pattern := range m.ignorePatterns {
			if pattern.MatchString(path) {
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
	// Compile patterns if needed (supports config changes after initialization)
	m.compileIgnorePatternsIfNeeded()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check pre-compiled patterns (much faster than compiling on every request)
			path := r.URL.Path
			for _, pattern := range m.ignorePatterns {
				if pattern.MatchString(path) {
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
