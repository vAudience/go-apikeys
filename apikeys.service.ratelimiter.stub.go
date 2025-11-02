// Package apikeys provides API key authentication and management middleware for Go applications.
//
// This file contains a STUB rate limiter that always allows requests with warnings.
// This is a placeholder until the external rate limiting package is ready.
package apikeys

import (
	"context"
	"sync"

	"go.uber.org/zap"
)

// StubRateLimiter is a placeholder rate limiter that always allows requests
// and logs warnings. Use this during development or when external rate limiting
// is handled by infrastructure (API Gateway, Nginx, etc.)
type StubRateLimiter struct {
	logger      *zap.Logger
	warningOnce sync.Once
}

// NewStubRateLimiter creates a new stub rate limiter
func NewStubRateLimiter(logger *zap.Logger) *StubRateLimiter {
	stub := &StubRateLimiter{
		logger: logger.Named(CLASS_RATE_LIMITER),
	}

	// Log warning on first creation
	stub.warningOnce.Do(func() {
		stub.logger.Warn("╔═══════════════════════════════════════════════════════════════════════════╗")
		stub.logger.Warn("║ STUB RATE LIMITER ACTIVE - ALL REQUESTS ALLOWED                          ║")
		stub.logger.Warn("╠═══════════════════════════════════════════════════════════════════════════╣")
		stub.logger.Warn("║ This is a placeholder implementation for development/testing.            ║")
		stub.logger.Warn("║ Production deployments should:                                            ║")
		stub.logger.Warn("║   1. Use external rate limiting (API Gateway, Nginx, Cloudflare)        ║")
		stub.logger.Warn("║   2. Replace with production rate limiter when available                 ║")
		stub.logger.Warn("║   3. Monitor request rates at infrastructure level                       ║")
		stub.logger.Warn("╚═══════════════════════════════════════════════════════════════════════════╝")
	})

	return stub
}

// Allow always returns true (allows all requests) with a debug log
func (s *StubRateLimiter) Allow(ctx context.Context, framework HTTPFramework, req interface{}) (bool, error) {
	// Log periodically (not on every request to avoid spam)
	s.logger.Debug("Rate limiter stub: allowing request (no rate limiting active)",
		zap.String("path", framework.GetRequestPath(req)))

	return true, nil
}

// Reset is a no-op for the stub
func (s *StubRateLimiter) Reset(ctx context.Context, identifier string) error {
	s.logger.Debug("Rate limiter stub: reset called (no-op)",
		zap.String("identifier", identifier))
	return nil
}

// GetLimit returns 0 for the stub (unlimited)
func (s *StubRateLimiter) GetLimit(ctx context.Context, identifier string) (int, error) {
	return 0, nil // 0 = unlimited
}

// GetRemaining returns -1 for the stub (unlimited)
func (s *StubRateLimiter) GetRemaining(ctx context.Context, identifier string) (int, error) {
	return -1, nil // -1 = unlimited
}
