# Rate Limiting with go-apikeys

## Overview

go-apikeys focuses exclusively on **API key authentication and management**. For rate limiting functionality, we recommend integrating a specialized rate limiting library that best fits your needs.

## Why No Built-in Rate Limiting?

Following the Unix philosophy of "do one thing well," go-apikeys provides:
- ✅ Secure API key generation and validation
- ✅ Framework-agnostic middleware (Fiber, Mux, stdlib)
- ✅ Flexible storage via go-datarepository
- ✅ CRUD operations for key management

For rate limiting, you have the flexibility to:
- Choose the best rate limiting solution for your use case
- Compose your middleware stack exactly how you need it
- Avoid being locked into a single rate limiting implementation

## Recommended Solution: gorly

We recommend [gorly](https://github.com/itsatony/gorly) - a production-grade rate limiting library with:

- 🚀 **Battle-tested**: 744 tests, 74% coverage, zero race conditions
- 🎯 **Token bucket algorithm** with burst support
- 🏢 **Tier-based limiting** (Free, Premium, Enterprise)
- 📊 **Rich metadata**: Limit, Remaining, RetryAfter, ResetAt
- 🔄 **Multiple backends**: In-memory and Redis
- 🌐 **HTTP middleware** with automatic X-RateLimit-* headers

## Integration Example

### 1. Install gorly

```bash
go get github.com/itsatony/gorly
```

### 2. Basic Integration

```go
package main

import (
    "context"
    "log"
    "net/http"
    "time"

    "github.com/itsatony/go-datarepository"
    "github.com/itsatony/gorly"
    "github.com/itsatony/gorly/stores"
    apikeys "github.com/vaudience/go-apikeys/v2"
    "go.uber.org/zap"
)

func main() {
    logger, _ := zap.NewProduction()
    defer logger.Sync()

    // Setup repository for API keys
    repo, err := datarepository.CreateDataRepository("redis",
        datarepository.NewRedisConfig(
            "single;redis_stack;;;;;;0;localhost:6379",
            "myapp",
            ":",
            func(level, msg string) { logger.Info(msg) },
        ))
    if err != nil {
        log.Fatal(err)
    }

    // Setup go-apikeys
    apikeyConfig := &apikeys.Config{
        Repository:   repo,
        Logger:       logger,
        ApiKeyPrefix: "myapp_",
        Framework:    apikeys.NewStdlibFramework(),
        EnableCRUD:   true,
    }

    apikeyManager, err := apikeys.New(apikeyConfig)
    if err != nil {
        log.Fatal(err)
    }

    // Setup gorly rate limiter
    gorlyStore := stores.NewRedisStore(&stores.RedisConfig{
        Addr: "localhost:6379",
    })

    gorlyLimiter, err := gorly.NewSimple(
        gorlyStore,
        100,              // requests per window
        time.Minute,      // window duration
    )
    if err != nil {
        log.Fatal(err)
    }

    // Create middleware stack
    mux := http.NewServeMux()

    // Protected route
    mux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
        // Get API key info from context
        apiKeyInfo := apikeys.GetAPIKeyInfo(r.Context())

        // Check rate limit using gorly
        identity := gorly.NewAPIKeyContext(apiKeyInfo.APIKeyHash, "free")
        result, err := gorlyLimiter.Allow(r.Context(), identity)
        if err != nil {
            http.Error(w, "Rate limit check failed", http.StatusInternalServerError)
            return
        }

        if !result.Allowed {
            w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", result.Limit))
            w.Header().Set("X-RateLimit-Remaining", "0")
            w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", result.ResetAt.Unix()))
            w.Header().Set("Retry-After", fmt.Sprintf("%d", int(result.RetryAfter.Seconds())))
            http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
            return
        }

        // Add rate limit headers to successful responses
        w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", result.Limit))
        w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", result.Remaining))
        w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", result.ResetAt.Unix()))

        w.Write([]byte("Success!"))
    })

    // Apply go-apikeys middleware
    handler := apikeyManager.Middleware()(mux)

    log.Println("Server starting on :8080")
    http.ListenAndServe(":8080", handler)
}
```

### 3. Tier-Based Rate Limiting

Map API key roles/metadata to gorly tiers for differentiated rate limiting:

```go
// Extract tier from API key info
func getTierFromAPIKey(apiKeyInfo *apikeys.APIKeyInfo) string {
    // Option 1: Check metadata
    if tier, ok := apiKeyInfo.Metadata["tier"].(string); ok {
        return tier
    }

    // Option 2: Check roles
    for _, role := range apiKeyInfo.Roles {
        switch role {
        case "enterprise", "admin":
            return gorly.TierEnterprise
        case "premium", "pro":
            return gorly.TierPremium
        }
    }

    return gorly.TierFree
}

// In your handler
tier := getTierFromAPIKey(apiKeyInfo)
identity := gorly.NewAPIKeyContext(apiKeyInfo.APIKeyHash, tier)
result, err := gorlyLimiter.Allow(r.Context(), identity)
```

### 4. Middleware Helper

Create a reusable middleware helper:

```go
func RateLimitMiddleware(limiter *gorly.Limiter) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Get API key info (set by go-apikeys middleware)
            apiKeyInfo := apikeys.GetAPIKeyInfo(r.Context())
            if apiKeyInfo == nil {
                // No API key = no rate limiting (or return error)
                next.ServeHTTP(w, r)
                return
            }

            // Determine tier
            tier := getTierFromAPIKey(apiKeyInfo)

            // Check rate limit
            identity := gorly.NewAPIKeyContext(apiKeyInfo.APIKeyHash, tier)
            result, err := limiter.Allow(r.Context(), identity)

            // Always add rate limit headers
            if result != nil {
                w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", result.Limit))
                w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", result.Remaining))
                w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", result.ResetAt.Unix()))
            }

            if err != nil {
                http.Error(w, "Rate limit check failed", http.StatusInternalServerError)
                return
            }

            if !result.Allowed {
                w.Header().Set("Retry-After", fmt.Sprintf("%d", int(result.RetryAfter.Seconds())))
                http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}

// Usage
handler := RateLimitMiddleware(gorlyLimiter)(
    apikeyManager.Middleware()(mux),
)
```

## Alternative Rate Limiters

If gorly doesn't fit your needs, consider:

### tollbooth
- Simple, popular Go rate limiter
- In-memory only
- Good for single-instance apps

```bash
go get github.com/didip/tollbooth/v7
```

### ulule/limiter
- Flexible rate limiting with multiple stores
- Redis, Memcached, in-memory
- Clean API

```bash
go get github.com/ulule/limiter/v3
```

### golang.org/x/time/rate
- Standard library rate limiter
- Token bucket algorithm
- No distributed support

```go
import "golang.org/x/time/rate"
```

## Design Philosophy

By separating concerns:

1. **go-apikeys** handles authentication
2. **Your rate limiter** handles request throttling
3. **Your framework** handles routing

You get:
- ✅ Best-in-class solutions for each concern
- ✅ Freedom to swap components
- ✅ Simplified testing and maintenance
- ✅ Clear separation of responsibilities

## Migration from v1.x

If you were using go-apikeys v1.x rate limiting:

1. Remove `EnableRateLimit` and `RateLimitRules` from config
2. Choose a rate limiting library (we recommend gorly)
3. Add rate limiting middleware after go-apikeys middleware
4. Map your old rules to the new limiter's configuration

Your API key authentication continues to work unchanged!

## Questions?

- For go-apikeys issues: https://github.com/vaudience/go-apikeys/issues
- For gorly issues: https://github.com/itsatony/gorly/issues
