package apikeys

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
)

func (m *APIKeyManager) fiberMiddleware() fiber.Handler {
	// Compile patterns if needed (supports config changes after initialization)
	m.compileIgnorePatternsIfNeeded()

	return func(c *fiber.Ctx) error {
		// Start timing for latency measurement
		start := time.Now()

		// Extract request context
		ctx := c.Context()
		path := c.Path()
		method := c.Method()
		ip := c.IP()
		userAgent := c.Get("User-Agent")

		// Check pre-compiled patterns (much faster than compiling on every request)
		for _, pattern := range m.ignorePatterns {
			if pattern.MatchString(path) {
				m.logger.Debug("Authentication skipped for ignored path",
					zap.String("path", path),
					zap.String("method", method),
					zap.String("ip", ip))
				return c.Next()
			}
		}

		// Extract API key from header
		apiKey := c.Get(m.config.HeaderKey)
		keyProvided := apiKey != ""

		// Attempt authentication
		apiKeyInfo, err := m.GetAPIKeyInfo(ctx, apiKey)
		latency := time.Since(start)

		// Prepare actor info for audit logging
		actor := ActorInfo{
			IPAddress: ip,
			UserAgent: userAgent,
		}

		// Handle authentication failure
		if err != nil {
			// Extract error type for metrics
			errorType := getErrorType(err)

			// Log authentication failure
			m.logger.Warn("Authentication failed",
				zap.String("path", path),
				zap.String("method", method),
				zap.String("ip", ip),
				zap.Bool("key_provided", keyProvided),
				zap.String("error_type", errorType),
				zap.Duration("latency", latency))

			// Record metrics
			if m.observability != nil && m.observability.Metrics != nil {
				m.observability.Metrics.RecordAuthAttempt(ctx, false, latency, map[string]string{
					"endpoint":   path,
					"error_type": errorType,
				})
				m.observability.Metrics.RecordAuthError(ctx, errorType, map[string]string{
					"endpoint": path,
				})
			}

			// Record audit event
			if m.observability != nil && m.observability.Audit != nil {
				auditEvent := &AuthAttemptEvent{
					BaseAuditEvent: NewBaseAuditEvent(EventTypeAuthFailure, actor, ResourceInfo{
						Type: "endpoint",
						ID:   path,
					}, OutcomeFailure),
					Method:       "api_key",
					KeyProvided:  keyProvided,
					KeyValid:     false,
					KeyFound:     false,
					LatencyMS:    latency.Milliseconds(),
					Endpoint:     path,
					HTTPMethod:   method,
					ErrorCode:    errorType,
					CacheHit:     false,
				}
				m.observability.Audit.LogAuthAttempt(ctx, auditEvent)
			}

			// Return generic unauthorized message for all auth failures
			// to prevent information leakage (timing attacks, key enumeration)
			return c.Status(fiber.StatusUnauthorized).SendString(ErrUnauthorized.Error())
		}

		// Authentication successful
		actor.UserID = apiKeyInfo.UserID
		actor.OrgID = apiKeyInfo.OrgID
		actor.APIKeyHash = apiKeyInfo.APIKeyHash

		// Log successful authentication (debug level - can be high volume)
		m.logger.Debug("Authentication successful",
			zap.String("user_id", apiKeyInfo.UserID),
			zap.String("org_id", apiKeyInfo.OrgID),
			zap.String("path", path),
			zap.String("method", method),
			zap.Duration("latency", latency))

		// Record metrics
		if m.observability != nil && m.observability.Metrics != nil {
			m.observability.Metrics.RecordAuthAttempt(ctx, true, latency, map[string]string{
				"org_id":   apiKeyInfo.OrgID,
				"endpoint": path,
			})
		}

		// Record audit event (may be sampled for high volume)
		if m.observability != nil && m.observability.Audit != nil {
			auditEvent := &AuthAttemptEvent{
				BaseAuditEvent: NewBaseAuditEvent(EventTypeAuthSuccess, actor, ResourceInfo{
					Type: "endpoint",
					ID:   path,
				}, OutcomeSuccess),
				Method:       "api_key",
				KeyProvided:  true,
				KeyValid:     true,
				KeyFound:     true,
				LatencyMS:    latency.Milliseconds(),
				Endpoint:     path,
				HTTPMethod:   method,
				CacheHit:     false, // TODO: track cache hit/miss
			}
			m.observability.Audit.LogAuthAttempt(ctx, auditEvent)
		}

		// Store API key info in context for downstream handlers
		c.Locals(LOCALS_KEY_APIKEYS, apiKeyInfo)
		return c.Next()
	}
}

func (m *APIKeyManager) standardMiddleware() func(http.Handler) http.Handler {
	// Compile patterns if needed (supports config changes after initialization)
	m.compileIgnorePatternsIfNeeded()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Start timing for latency measurement
			start := time.Now()

			// Extract request context
			ctx := r.Context()
			path := r.URL.Path
			method := r.Method
			ip := getClientIP(r)
			userAgent := r.Header.Get("User-Agent")

			// Check pre-compiled patterns (much faster than compiling on every request)
			for _, pattern := range m.ignorePatterns {
				if pattern.MatchString(path) {
					m.logger.Debug("Authentication skipped for ignored path",
						zap.String("path", path),
						zap.String("method", method),
						zap.String("ip", ip))
					next.ServeHTTP(w, r)
					return
				}
			}

			// Extract API key from header
			apiKey := r.Header.Get(m.config.HeaderKey)
			keyProvided := apiKey != ""

			// Attempt authentication
			apiKeyInfo, err := m.GetAPIKeyInfo(ctx, apiKey)
			latency := time.Since(start)

			// Prepare actor info for audit logging
			actor := ActorInfo{
				IPAddress: ip,
				UserAgent: userAgent,
			}

			// Handle authentication failure
			if err != nil {
				// Extract error type for metrics
				errorType := getErrorType(err)

				// Log authentication failure
				m.logger.Warn("Authentication failed",
					zap.String("path", path),
					zap.String("method", method),
					zap.String("ip", ip),
					zap.Bool("key_provided", keyProvided),
					zap.String("error_type", errorType),
					zap.Duration("latency", latency))

				// Record metrics
				if m.observability != nil && m.observability.Metrics != nil {
					m.observability.Metrics.RecordAuthAttempt(ctx, false, latency, map[string]string{
						"endpoint":   path,
						"error_type": errorType,
					})
					m.observability.Metrics.RecordAuthError(ctx, errorType, map[string]string{
						"endpoint": path,
					})
				}

				// Record audit event
				if m.observability != nil && m.observability.Audit != nil {
					auditEvent := &AuthAttemptEvent{
						BaseAuditEvent: NewBaseAuditEvent(EventTypeAuthFailure, actor, ResourceInfo{
							Type: "endpoint",
							ID:   path,
						}, OutcomeFailure),
						Method:       "api_key",
						KeyProvided:  keyProvided,
						KeyValid:     false,
						KeyFound:     false,
						LatencyMS:    latency.Milliseconds(),
						Endpoint:     path,
						HTTPMethod:   method,
						ErrorCode:    errorType,
						CacheHit:     false,
					}
					m.observability.Audit.LogAuthAttempt(ctx, auditEvent)
				}

				// Return generic unauthorized message for all auth failures
				// to prevent information leakage (timing attacks, key enumeration)
				http.Error(w, ErrUnauthorized.Error(), http.StatusUnauthorized)
				return
			}

			// Authentication successful
			actor.UserID = apiKeyInfo.UserID
			actor.OrgID = apiKeyInfo.OrgID
			actor.APIKeyHash = apiKeyInfo.APIKeyHash

			// Log successful authentication (debug level - can be high volume)
			m.logger.Debug("Authentication successful",
				zap.String("user_id", apiKeyInfo.UserID),
				zap.String("org_id", apiKeyInfo.OrgID),
				zap.String("path", path),
				zap.String("method", method),
				zap.Duration("latency", latency))

			// Record metrics
			if m.observability != nil && m.observability.Metrics != nil {
				m.observability.Metrics.RecordAuthAttempt(ctx, true, latency, map[string]string{
					"org_id":   apiKeyInfo.OrgID,
					"endpoint": path,
				})
			}

			// Record audit event (may be sampled for high volume)
			if m.observability != nil && m.observability.Audit != nil {
				auditEvent := &AuthAttemptEvent{
					BaseAuditEvent: NewBaseAuditEvent(EventTypeAuthSuccess, actor, ResourceInfo{
						Type: "endpoint",
						ID:   path,
					}, OutcomeSuccess),
					Method:       "api_key",
					KeyProvided:  true,
					KeyValid:     true,
					KeyFound:     true,
					LatencyMS:    latency.Milliseconds(),
					Endpoint:     path,
					HTTPMethod:   method,
					CacheHit:     false, // TODO: track cache hit/miss
				}
				m.observability.Audit.LogAuthAttempt(ctx, auditEvent)
			}

			// Store API key info in context for downstream handlers
			// Use typed context key for stdlib to prevent collisions
			ctx = context.WithValue(ctx, contextKeyAPIKeyInfo, apiKeyInfo)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

// getClientIP extracts the client IP address from the request.
// It checks X-Forwarded-For and X-Real-IP headers first, then falls back to RemoteAddr.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (may contain multiple IPs, first is client)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take first IP if multiple are present
		for i, c := range xff {
			if c == ',' {
				return xff[:i]
			}
		}
		return xff
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr (may include port)
	ip := r.RemoteAddr
	for i, c := range ip {
		if c == ':' {
			return ip[:i]
		}
	}
	return ip
}

// getErrorType extracts a string representation of the error type for metrics/logging.
func getErrorType(err error) string {
	if err == nil {
		return "none"
	}

	// Check for known error types
	switch err {
	case ErrUnauthorized:
		return "unauthorized"
	case ErrAPIKeyRequired:
		return "key_required"
	case ErrAPIKeyNotFound:
		return "key_not_found"
	case ErrInvalidAPIKey:
		return "key_invalid"
	case ErrRepositoryRequired:
		return "repository_required"
	default:
		// Return error message for unknown errors
		errMsg := err.Error()
		// Truncate long error messages
		if len(errMsg) > 50 {
			return fmt.Sprintf("%.47s...", errMsg)
		}
		return errMsg
	}
}
