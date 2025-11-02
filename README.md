# go-apikeys

A production-ready, framework-agnostic API key authentication and management middleware for Go web applications.

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Version

**v2.0.0** - Major release focusing on core API key authentication (production-ready)

## Features

### Core Features
- 🔐 **Secure API Key Management** - SHA3-512 hashing with salt, secure key generation
- 🚀 **Framework Agnostic** - Built-in support for Fiber v2, Gorilla Mux, and stdlib net/http
- 📦 **Clean Architecture** - Service layer, repository pattern, dependency injection
- 🔄 **CRUD Operations** - Full API key lifecycle management with REST endpoints
- 🛡️ **Thread Safe** - No race conditions, concurrent request handling
- 📊 **Structured Logging** - Uber Zap integration for production-grade logging
- 🔧 **Flexible Storage** - Works with any repository implementing the interface
- 🔌 **Composable** - Focus on API keys; integrate your choice of rate limiter ([see guide](docs/RATE_LIMITING.md))

### New in v2.0.0
- 🎯 **Focused Architecture** - Removed built-in rate limiting to follow Unix philosophy ("do one thing well")
- 🧩 **Composable Design** - Users now choose and integrate their preferred rate limiting solution
- 📚 **Comprehensive Guide** - New `docs/RATE_LIMITING.md` with gorly integration examples
- 🧹 **Cleaner Codebase** - Removed 1,324 lines of rate limiting code
- 🔄 **Breaking Change** - Removed `EnableRateLimit` and `RateLimitRules` from configuration
- ✅ **Migration Support** - See [CHANGELOG.md](CHANGELOG.md) for complete migration guide

<details>
<summary><b>Previous Versions</b></summary>

### v1.0.1
- 🐛 **Critical Bug Fixes** - Fixed data races in CreateAPIKey and UpdateAPIKey operations
- 🧪 **Enhanced Testing** - 69.1% coverage with 145+ test cases including 15 concurrent scenarios
- ✅ **Production Validated** - 100-iteration stress test with zero race conditions detected
- 🔒 **Thread Safety** - All concurrent operations properly synchronized

### v1.0.0
- ✅ **Bootstrap Service** - Automatic system admin key creation with security warnings
- ✅ **Version Management** - Multi-dimensional versioning with go-version
- ✅ **Zero Code Duplication** - Handler core pattern eliminates framework-specific logic duplication
- ✅ **Clean Architecture** - Service layer, repository pattern, comprehensive error handling
- ✅ **go-cuserr Integration** - Standardized error handling and categorization

</details>

## Installation

```bash
go get github.com/vaudience/go-apikeys@v2.0.0
```

### Dependencies

```bash
# Core dependencies
go get github.com/itsatony/go-datarepository
go get github.com/itsatony/go-cuserr
go get github.com/itsatony/go-version
go get go.uber.org/zap
go get golang.org/x/crypto

# Framework-specific (install only what you need)
go get github.com/gofiber/fiber/v2        # For Fiber support
go get github.com/gorilla/mux             # For Gorilla Mux support
```

## Quick Start

### Basic Setup (stdlib net/http)

```go
package main

import (
    "log"
    "net/http"

    "github.com/itsatony/go-datarepository"
    "github.com/vaudience/go-apikeys"
    "go.uber.org/zap"
)

func main() {
    // Setup logger
    logger, _ := zap.NewProduction()
    defer logger.Sync()

    // Setup repository (Redis example)
    repo, err := datarepository.CreateDataRepository("redis",
        datarepository.NewRedisConfig(
            "single;redis_stack;;;;;;0;localhost:6379",
            "myapp_apikeys",
            ":",
            func(level, msg string) { logger.Info(msg) },
        ))
    if err != nil {
        log.Fatal(err)
    }

    // Configure API keys manager
    config := &apikeys.Config{
        Repository:      repo,
        Logger:          logger,
        ApiKeyPrefix:    "myapp_",
        ApiKeyLength:    32,
        HeaderKey:       "X-API-Key",
        EnableCRUD:      true,
        EnableBootstrap: true,  // Auto-create system admin key on first run
    }

    // Create manager
    manager, err := apikeys.New(config)
    if err != nil {
        log.Fatal(err)
    }

    // Setup routes
    mux := http.NewServeMux()

    // Protected route
    mux.HandleFunc("/api/protected", func(w http.ResponseWriter, r *http.Request) {
        // API key validation happens in middleware
        userID := manager.UserID(r)
        w.Write([]byte("Hello, " + userID))
    })

    // Wrap with authentication middleware (type-safe!)
    http.ListenAndServe(":8080", manager.StdlibMiddleware()(mux))
}
```

## Framework Examples

### Fiber v2

```go
package main

import (
    "github.com/gofiber/fiber/v2"
    "github.com/itsatony/go-datarepository"
    "github.com/vaudience/go-apikeys"
    "go.uber.org/zap"
)

func main() {
    logger, _ := zap.NewProduction()
    defer logger.Sync()

    repo, _ := datarepository.CreateDataRepository("redis", /* config */)

    config := &apikeys.Config{
        Repository:   repo,
        Logger:       logger,
        ApiKeyPrefix: "myapp_",
        ApiKeyLength: 32,
        HeaderKey:    "X-API-Key",
        EnableCRUD:   true,
        Framework:    &apikeys.FiberFramework{},  // Set Fiber framework
    }

    manager, _ := apikeys.New(config)

    app := fiber.New()

    // Apply middleware (type-safe!)
    app.Use(manager.FiberMiddleware())

    // Protected route
    app.Get("/api/protected", func(c *fiber.Ctx) error {
        userID := manager.UserID(c)
        return c.SendString("Hello, " + userID)
    })

    app.Listen(":8080")
}
```

### Gorilla Mux

```go
package main

import (
    "net/http"

    "github.com/gorilla/mux"
    "github.com/itsatony/go-datarepository"
    "github.com/vaudience/go-apikeys"
    "go.uber.org/zap"
)

func main() {
    logger, _ := zap.NewProduction()
    defer logger.Sync()

    repo, _ := datarepository.CreateDataRepository("redis", /* config */)

    config := &apikeys.Config{
        Repository:   repo,
        Logger:       logger,
        ApiKeyPrefix: "myapp_",
        ApiKeyLength: 32,
        HeaderKey:    "X-API-Key",
        EnableCRUD:   true,
        Framework:    &apikeys.GorillaMuxFramework{},  // Set Mux framework
    }

    manager, _ := apikeys.New(config)

    r := mux.NewRouter()

    // Apply middleware (type-safe!)
    r.Use(manager.StdlibMiddleware())

    // Protected route
    r.HandleFunc("/api/protected", func(w http.ResponseWriter, r *http.Request) {
        userID := manager.UserID(r)
        w.Write([]byte("Hello, " + userID))
    })

    http.ListenAndServe(":8080", r)
}
```

## Configuration

### Config Structure

```go
type Config struct {
    // Required
    Repository   datarepository.DataRepository  // Storage backend
    Logger       *zap.Logger                     // Structured logger

    // API Key Settings
    ApiKeyPrefix string  // Prefix for generated keys (default: "gak_")
    ApiKeyLength int     // Length of random part (default: 32)
    HeaderKey    string  // Request header name (default: "X-API-Key")

    // Features
    EnableCRUD       bool   // Enable CRUD REST endpoints (default: false)
    EnableBootstrap  bool   // Auto-create system admin key (default: false)

    // Optional
    Framework                      HTTPFramework  // Framework adapter
    IgnoreApiKeyForRoutePatterns  []string       // Skip auth for these routes
    BootstrapConfig               *BootstrapConfig
}
```

### Bootstrap Configuration

The bootstrap service automatically creates a system admin API key on first run:

```go
config := &apikeys.Config{
    EnableBootstrap: true,
    BootstrapConfig: &apikeys.BootstrapConfig{
        IUnderstandSecurityRisks: true,  // REQUIRED: Acknowledge security implications
        AdminUserID:              "system-admin",
        AdminOrgID:               "system",
        AdminEmail:               "admin@example.com",
        RecoveryPath:             "./system-admin-key.txt",  // Optional: save key to file
    },
    // ... other config
}
```

**⚠️ SECURITY WARNING**: Bootstrap mode logs the API key in clear text and optionally writes it to a file. This is a **documented security lapse** for initial setup convenience. Disable `EnableBootstrap` after first run.

#### Production Environment Protection

Bootstrap **automatically detects production environments** and refuses to run for safety:

```bash
# Production environment detection via:
ENV=production           # or
ENVIRONMENT=production   # or
GO_ENV=production
```

When production is detected, bootstrap will fail with:
```
Bootstrap is disabled in production for security.
Set AllowBootstrapInProduction=true to override,
or run bootstrap in a non-production environment.
```

**To explicitly allow bootstrap in production** (not recommended):

```go
BootstrapConfig: &apikeys.BootstrapConfig{
    IUnderstandSecurityRisks:   true,
    AllowBootstrapInProduction: true,  // ⚠️ Use with extreme caution
    AdminUserID:                "system-admin",
    AdminOrgID:                 "system",
    // ...
}
```

**RECOMMENDATION**:
1. Run bootstrap **once** in development/staging
2. Save the generated API key securely (password manager, secrets vault)
3. Deploy to production with `EnableBootstrap: false`
4. Never commit the recovery file to version control

### Rate Limiting

go-apikeys v2.0.0+ focuses solely on API key authentication. For rate limiting, integrate your choice of rate limiting library.

**Recommended**: [gorly](https://github.com/itsatony/gorly) - production-grade rate limiting with tier support

See [docs/RATE_LIMITING.md](docs/RATE_LIMITING.md) for integration guide and examples.

## API Key Management

### Creating API Keys

```go
ctx := context.Background()

// Create with auto-generated key
apiKeyInfo := &apikeys.APIKeyInfo{
    UserID: "user-123",
    OrgID:  "org-456",
    Name:   "Production API Key",
    Email:  "user@example.com",
    Roles:  []string{"admin", "user"},
}

created, err := manager.CreateAPIKey(ctx, apiKeyInfo)
if err != nil {
    log.Fatal(err)
}

// Save the API key - it's only returned once!
fmt.Println("API Key:", created.APIKey)  // e.g., "myapp_xK8mP2nQ..."
fmt.Println("Hint:", created.APIKeyHint) // e.g., "myapp...Q..."
```

### Retrieving API Keys

```go
// By plain API key
apiKeyInfo, err := manager.GetAPIKeyInfo(ctx, "myapp_xK8mP2nQ...")

// By hash
apiKeyInfo, err := manager.GetAPIKeyInfo(ctx, "abc123...")

// Access information
fmt.Println("User ID:", apiKeyInfo.UserID)
fmt.Println("Org ID:", apiKeyInfo.OrgID)
fmt.Println("Roles:", apiKeyInfo.Roles)
```

### Updating API Keys

```go
apiKeyInfo.Name = "Updated Name"
apiKeyInfo.Roles = []string{"user"}

err := manager.UpdateAPIKey(ctx, apiKeyInfo)
```

### Deleting API Keys

```go
err := manager.DeleteAPIKey(ctx, apiKeyHash)
```

### Searching API Keys

```go
apiKeys, total, err := manager.SearchAPIKeys(ctx, offset, limit)
```

## Middleware Usage

### Extracting API Key Information

The middleware automatically validates API keys and injects information into the request context:

```go
// In your handler
func MyHandler(c *fiber.Ctx) error {  // or http.ResponseWriter, *http.Request
    userID := manager.UserID(c)
    orgID := manager.OrgID(c)
    email := manager.Email(c)
    name := manager.Name(c)
    metadata := manager.Metadata(c)

    // Full info
    apiKeyInfo := manager.Get(c)

    return c.SendString("Hello, " + userID)
}
```

### Ignoring Routes

Some routes (health checks, metrics) don't need authentication:

```go
config := &apikeys.Config{
    IgnoreApiKeyForRoutePatterns: []string{
        "/health",
        "/metrics",
        "/api/public/.*",
    },
    // ... other config
}
```

## System Admin

System admin API keys have elevated privileges for CRUD operations:

```go
apiKeyInfo := &apikeys.APIKeyInfo{
    UserID: "admin-user",
    OrgID:  "system",
    Metadata: map[string]any{
        apikeys.METADATA_KEY_SYSTEM_ADMIN: true,
    },
}

// Check if system admin
isAdmin := manager.service.IsSystemAdmin(apiKeyInfo)
```

## Error Handling

All errors use `go-cuserr` for consistent categorization:

```go
import "github.com/itsatony/go-cuserr"

apiKeyInfo, err := manager.GetAPIKeyInfo(ctx, apiKey)
if err != nil {
    if err == apikeys.ErrAPIKeyNotFound {
        // Handle not found
    } else if cuserr.IsValidationError(err) {
        // Handle validation error
    } else {
        // Handle other errors
    }
}
```

## Testing

The package includes comprehensive test coverage:

```bash
# Run all tests
go test ./...

# Run with race detector
go test -race ./...

# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

**Test Statistics**:
- 130+ test cases
- 33.4% overall coverage
- 100% coverage of middleware (critical authentication path)
- 91.3% coverage of handler core
- Zero race conditions

## Architecture

### Clean Architecture Layers

```
┌─────────────────────────────────────────┐
│         HTTP Layer (Framework)          │
│  (Fiber / Gorilla Mux / stdlib)        │
├─────────────────────────────────────────┤
│         Handler Core (Business)         │
│  (Framework-agnostic logic)            │
├─────────────────────────────────────────┤
│         Service Layer                   │
│  (APIKeyService, BootstrapService)     │
├─────────────────────────────────────────┤
│         Repository Interface            │
│  (APIKeyRepository)                     │
├─────────────────────────────────────────┤
│         Storage Implementation          │
│  (go-datarepository: Redis, etc.)      │
└─────────────────────────────────────────┘
```

### Key Design Patterns

- **Service Layer Pattern**: Business logic isolated from HTTP concerns
- **Repository Pattern**: Storage abstraction for flexibility
- **Adapter Pattern**: Multiple framework support without duplication
- **Singleton Pattern**: Version management with thread-safe initialization

## Migration Guides

### v1.x → v2.0.0

#### Breaking Changes

**Removed Built-in Rate Limiting:**
- Removed `EnableRateLimit` config field
- Removed `RateLimitRules` config field
- Removed all rate limiting functionality (1,324 lines)

**Rationale:** Following Unix philosophy, go-apikeys now focuses exclusively on API key authentication. Users integrate their preferred rate limiting solution.

#### Migration Steps

**If you were NOT using rate limiting:**
- No changes required! Update your dependency:
  ```bash
  go get -u github.com/vaudience/go-apikeys@v2.0.0
  ```

**If you were using rate limiting:**
1. Remove `EnableRateLimit` and `RateLimitRules` from your config
2. Choose a rate limiting library (we recommend [gorly](https://github.com/itsatony/gorly))
3. Integrate rate limiting middleware after go-apikeys middleware
4. See [docs/RATE_LIMITING.md](docs/RATE_LIMITING.md) for complete integration examples

**Example Migration:**
```go
// OLD (v1.x)
config := &apikeys.Config{
    EnableRateLimit: true,
    RateLimitRules: []apikeys.RateLimitRule{...},
}

// NEW (v2.0.0) - No rate limiting in config
config := &apikeys.Config{
    Repository: repo,
    Logger:     logger,
    Framework:  apikeys.NewStdlibFramework(),
}

// Integrate gorly or your preferred rate limiter
// See docs/RATE_LIMITING.md for complete examples
```

### v0.x → v1.0.0

### Breaking Changes

1. **New Required Dependencies**
   ```bash
   go get github.com/itsatony/go-cuserr
   go get github.com/itsatony/go-version
   ```

2. **Config Changes**
   - Removed: `SystemAPIKey` field
   - Added: `EnableBootstrap`, `BootstrapConfig` for system admin setup
   - Changed: `Framework` field is now optional (defaults to stdlib)

3. **Error Handling**
   - All errors now use `go-cuserr`
   - Old: Check error strings
   - New: Use error type checking (`err == apikeys.ErrAPIKeyNotFound`)

4. **Bootstrap Replaces SystemAPIKey**
   ```go
   // Old (v0.x)
   config := &apikeys.Config{
       SystemAPIKey: "hardcoded-key",
   }

   // New (v1.0.0)
   config := &apikeys.Config{
       EnableBootstrap: true,
       BootstrapConfig: &apikeys.BootstrapConfig{
           UserID: "system-admin",
           OrgID:  "system",
       },
   }
   ```

6. **Method Signatures**
   - All CRUD methods now require `context.Context` as first parameter
   - Old: `GetAPIKeyInfo(apiKey string)`
   - New: `GetAPIKeyInfo(ctx context.Context, apiKey string)`

### Step-by-Step Migration

1. **Update dependencies**
   ```bash
   go get -u github.com/vaudience/go-apikeys@v1.0.0
   go get github.com/itsatony/go-cuserr
   go get github.com/itsatony/go-version
   ```

2. **Update imports**
   ```go
   import (
       "context"
       "github.com/vaudience/go-apikeys"
       "github.com/itsatony/go-cuserr"
   )
   ```

3. **Update config**
   ```go
   // Add context to method calls
   ctx := context.Background()

   // Replace SystemAPIKey with Bootstrap
   config.EnableBootstrap = true
   config.BootstrapConfig = &apikeys.BootstrapConfig{
       UserID: "admin",
       OrgID:  "system",
   }

   // Update rate limiting
   config.EnableRateLimit = false  // Or implement custom limiter
   ```

4. **Update CRUD calls**
   ```go
   // Add context parameter to all calls
   apiKeyInfo, err := manager.GetAPIKeyInfo(ctx, apiKey)
   err = manager.UpdateAPIKey(ctx, apiKeyInfo)
   err = manager.DeleteAPIKey(ctx, apiKeyHash)
   keys, total, err := manager.SearchAPIKeys(ctx, 0, 10)
   ```

5. **Update error handling**
   ```go
   if err == apikeys.ErrAPIKeyNotFound {
       // Handle not found
   }
   ```

6. **Test thoroughly**
   - Run your test suite
   - Test authentication flows
   - Verify API key CRUD operations
   - Check error handling

## Troubleshooting

### Common Issues and Solutions

#### Authentication Failed (401 Unauthorized)

**Symptom**: All requests return `401 Unauthorized`

**Common Causes**:
1. API key not provided or incorrect format
2. API key not found in database
3. Wrong header name

**Solutions**:
```go
// Check your header configuration
config.HeaderKey = "X-API-Key" // Default, verify this matches your requests

// Verify API key format
// Should be: {prefix}_{random_string}
// Example: gak_abc123xyz456

// Enable debug logging
logger, _ := zap.NewDevelopment() // Use Development for detailed logs
config.Logger = logger
```

**Testing**:
```bash
# Check if API key exists
curl -H "X-API-Key: your_key_here" http://localhost:8080/api/protected

# If bootstrap is enabled, watch logs for:
# "╔═══════════════════════════════════════════════════════════════════════════╗"
# "║ BOOTSTRAP API KEY CREATED - STORE SECURELY AND DELETE THIS LOG!          ║"
```

#### Bootstrap Key Not Created

**Symptom**: Bootstrap doesn't create system admin key

**Common Causes**:
1. `IUnderstandSecurityRisks` not set to true
2. System admin key already exists
3. Bootstrap not enabled

**Solutions**:
```go
// Ensure bootstrap is properly configured
config.EnableBootstrap = true
config.BootstrapConfig = &apikeys.BootstrapConfig{
    IUnderstandSecurityRisks: true, // REQUIRED - must be explicitly set
    AdminUserID:              "bootstrap-admin",
    AdminOrgID:               "system",
}

// Check logs for:
// "Bootstrap not needed - system admin key already exists"
// This means a system admin key already exists
```

**Reset Bootstrap**:
```bash
# If using Redis, clear all data
redis-cli FLUSHDB

# Or delete specific keys
redis-cli KEYS "go_apikeys:*" | xargs redis-cli DEL
```

#### Database Connection Failed

**Symptom**: `failed to connect to Redis` or similar database errors

**Solutions**:
```go
// Verify connection string format
// Format: "mode;type;;;;;;database;host:port"
connStr := "single;redis_stack;;;;;;0;localhost:6379"

// Test connection separately
repo, err := datarepository.CreateDataRepository("redis",
    datarepository.NewRedisConfig(
        connStr,
        "go_apikeys",
        ":",
        func(level, msg string) {
            log.Printf("[%s] %s", level, msg)
        },
    ))
if err != nil {
    log.Fatalf("Connection failed: %v", err)
}
```

**Docker Redis**:
```bash
# Start Redis with docker-compose (from examples/ directory)
cd examples
docker-compose up -d

# Check Redis is running
docker-compose ps
```

#### Type Assertion Errors

**Symptom**: `panic: interface conversion` or type assertion errors

**Common Causes**:
- Using wrong middleware method for your framework
- Mixing Fiber and stdlib types

**Solutions**:
```go
// FOR FIBER: Use FiberMiddleware()
app := fiber.New()
app.Use(manager.FiberMiddleware()) // NOT Middleware()

// FOR STDLIB/MUX: Use StdlibMiddleware()
mux := http.NewServeMux()
handler := manager.StdlibMiddleware()(yourHandler)

// Deprecated (avoid):
app.Use(manager.Middleware().(fiber.Handler)) // Type assertion required - error-prone
```

#### CRUD Routes Not Working (404 Not Found)

**Symptom**: `/apikeys` endpoints return 404

**Common Causes**:
1. CRUD not enabled
2. Routes not registered
3. Middleware applied before CRUD routes

**Solutions**:
```go
// Enable CRUD in config
config.EnableCRUD = true

// Register CRUD routes AFTER applying middleware
// FIBER:
app.Use(manager.FiberMiddleware())
apikeys.RegisterCRUDRoutes(app, manager) // Order: app first, manager second

// STDLIB with Gorilla Mux:
router := mux.NewRouter()
apikeys.RegisterCRUDRoutes(router, manager)
```

#### Validation Errors

**Symptom**: `validation failed: user_id is required` or similar

**Common Causes**:
- Missing required fields
- Field length constraints violated
- Invalid email format

**Solutions**:
```go
// Ensure required fields are provided
apiKeyInfo := &apikeys.APIKeyInfo{
    UserID: "user123",     // Required, 1-100 chars
    OrgID:  "org456",      // Required, 1-100 chars
    Email:  "user@ex.com", // Optional, must be valid email if provided
    Name:   "My Key",      // Optional, 1-200 chars
}

// Check field constraints:
// - UserID: 1-100 characters
// - OrgID: 1-100 characters
// - Name: 1-200 characters
// - Email: 3-255 characters, valid format
// - Metadata: Max 10KB JSON
```

### Debugging Tips

#### Enable Detailed Logging

```go
// Use development logger for detailed output
logger, _ := zap.NewDevelopment()
config.Logger = logger

// Or customize log level
cfg := zap.NewDevelopmentConfig()
cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
logger, _ := cfg.Build()
config.Logger = logger
```

#### Inspect API Key Information

```go
// In your handler
apiKeyInfo := manager.Get(c)
log.Printf("User: %s, Org: %s, Roles: %v",
    apiKeyInfo.UserID,
    apiKeyInfo.OrgID,
    apiKeyInfo.Roles)

// Or use convenience methods
userID := manager.UserID(c)
metadata := manager.Metadata(c)
```

#### Test API Key Operations

```bash
# Create test key
curl -X POST http://localhost:8080/apikeys \
  -H "X-API-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"test","org_id":"test"}'

# List all keys
curl -H "X-API-Key: $ADMIN_KEY" \
  "http://localhost:8080/apikeys?offset=0&limit=10"

# Get specific key
curl -H "X-API-Key: $ADMIN_KEY" \
  "http://localhost:8080/apikeys/$KEY_HASH"
```

### Getting Help

If you're still experiencing issues:

1. **Check Examples**: See `examples/` directory for working implementations
2. **Read API Documentation**: See `api/openapi.yaml` for complete API specification
3. **Enable Debug Logging**: Use `zap.NewDevelopment()` for detailed logs
4. **Search Issues**: Check [GitHub Issues](https://github.com/vaudience/go-apikeys/issues) for similar problems
5. **Create Issue**: If problem persists, create a detailed issue with:
   - Go version (`go version`)
   - Package version
   - Minimal reproducible example
   - Full error message and stack trace
   - Configuration (redact sensitive data)

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for new functionality
4. Ensure all tests pass (`go test -race ./...`)
5. Commit changes (`git commit -m 'Add amazing feature'`)
6. Push to branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Development Setup

```bash
# Clone repository
git clone https://github.com/vaudience/go-apikeys.git
cd go-apikeys

# Install dependencies
go mod download

# Run tests
go test -v -race ./...

# Check coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/vaudience/go-apikeys/issues)
- **Documentation**: [GoDoc](https://pkg.go.dev/github.com/vaudience/go-apikeys)
- **API Specification**: See `api/openapi.yaml` for complete OpenAPI 3.0 spec
- **Examples**: See `examples/` directory for Fiber and stdlib implementations
- **Troubleshooting**: See "Troubleshooting" section above

## Credits

Developed and maintained by the Vaudience team.

### Dependencies

- [go-datarepository](https://github.com/itsatony/go-datarepository) - Flexible data storage
- [go-cuserr](https://github.com/itsatony/go-cuserr) - Custom error handling
- [go-version](https://github.com/itsatony/go-version) - Version management
- [zap](https://github.com/uber-go/zap) - Structured logging
- [fiber](https://github.com/gofiber/fiber) - Web framework (optional)
- [gorilla/mux](https://github.com/gorilla/mux) - HTTP router (optional)
