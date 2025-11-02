// Package apikeys provides API key authentication and management middleware for Go applications.
//
// This file defines the rate limiter interface for different implementations.
package apikeys

import (
	"context"
)

// RateLimiterInterface defines the interface for rate limiting implementations
type RateLimiterInterface interface {
	// Allow checks if a request is allowed based on rate limiting rules
	Allow(ctx context.Context, framework HTTPFramework, req interface{}) (bool, error)
}
