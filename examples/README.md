# go-apikeys Examples

This directory contains runnable examples demonstrating how to use go-apikeys with different HTTP frameworks.

## Prerequisites

- Go 1.24 or later
- Docker and Docker Compose (for Redis)

## Quick Start

### 1. Start Redis

```bash
cd examples
docker-compose up -d
```

Verify Redis is running:
```bash
docker-compose ps
# Should show go-apikeys-redis as "Up"
```

### 2. Run an Example

#### Fiber Example (Recommended for production)

```bash
cd fiber
go run main.go
```

The Fiber example demonstrates:
- API key authentication middleware
- CRUD endpoints for API key management
- Bootstrap mode for initial setup
- Type-safe middleware usage

#### Stdlib Example (Standard net/http)

```bash
cd stdlib
go run main.go
```

The stdlib example demonstrates:
- Using go-apikeys with standard library net/http
- Minimal dependencies
- Clean middleware integration

### 3. Test the API

#### Bootstrap (First Run Only)

On first startup, bootstrap creates an admin API key. Watch the console output for:

```
╔═══════════════════════════════════════════════════════════════════════════╗
║ BOOTSTRAP API KEY CREATED - STORE SECURELY AND DELETE THIS LOG!          ║
╠═══════════════════════════════════════════════════════════════════════════╣
║ API Key:  gak_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx                            ║
...
╚═══════════════════════════════════════════════════════════════════════════╝
```

**IMPORTANT**: Copy this API key immediately. It will only be shown once!

#### Test Authentication

```bash
# Without API key - should fail
curl http://localhost:8080/api/hello

# With API key - should succeed
curl -H "X-API-Key: gak_your_bootstrap_key_here" http://localhost:8080/api/hello
```

#### Create Additional API Keys

```bash
# Create a new API key
curl -X POST http://localhost:8080/apikeys \
  -H "X-API-Key: gak_your_bootstrap_key_here" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user123",
    "org_id": "org456",
    "email": "user@example.com",
    "name": "My API Key",
    "roles": ["user"],
    "metadata": {"env": "production"}
  }'
```

#### List API Keys

```bash
curl -H "X-API-Key: gak_your_bootstrap_key_here" \
  http://localhost:8080/apikeys?offset=0&limit=10
```

#### Get Specific API Key

```bash
# By hash
curl -H "X-API-Key: gak_your_bootstrap_key_here" \
  http://localhost:8080/apikeys/{hash}

# Or by plain key
curl -H "X-API-Key: gak_your_bootstrap_key_here" \
  http://localhost:8080/apikeys/gak_your_api_key_here
```

#### Update API Key

```bash
curl -X PUT http://localhost:8080/apikeys/{hash} \
  -H "X-API-Key: gak_your_bootstrap_key_here" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user123",
    "org_id": "org456",
    "name": "Updated Name",
    "roles": ["user", "admin"]
  }'
```

#### Delete API Key

```bash
curl -X DELETE http://localhost:8080/apikeys/{hash} \
  -H "X-API-Key: gak_your_bootstrap_key_here"
```

## Examples Overview

### Fiber Example

**File**: `fiber/main.go`

Features demonstrated:
- Fiber v2 integration
- Type-safe `FiberMiddleware()` method
- Bootstrap configuration with security acknowledgment
- CRUD route registration
- Structured logging with zap
- Redis data repository
- Protected and public routes

Key code snippets:

```go
// Create manager with type-safe middleware
manager, _ := apikeys.New(config)
app.Use(manager.FiberMiddleware())

// Register CRUD routes
apikeys.RegisterCRUDRoutes(manager, app)
```

### Stdlib Example

**File**: `stdlib/main.go`

Features demonstrated:
- Standard library net/http
- Type-safe `StdlibMiddleware()` method
- Gorilla Mux compatibility
- Manual route registration
- Minimal dependencies

Key code snippets:

```go
// Create manager with type-safe middleware
manager, _ := apikeys.New(config)

// Apply middleware
http.Handle("/", manager.StdlibMiddleware()(yourHandler))
```

## Configuration Options

Both examples demonstrate key configuration options:

### Basic Setup

```go
config := &apikeys.Config{
    Repository:   redisRepo,
    Framework:    apikeys.NewFiberFramework(), // or NewStdlibFramework()
    HeaderKey:    "X-API-Key",
    ApiKeyPrefix: "gak_",
    ApiKeyLength: 32,
    Logger:       logger,
}
```

### Enable CRUD Endpoints

```go
config.EnableCRUD = true
```

### Enable Bootstrap Mode

```go
config.EnableBootstrap = true
config.BootstrapConfig = &apikeys.BootstrapConfig{
    IUnderstandSecurityRisks: true, // REQUIRED - acknowledges plain-text logging
    AdminUserID:              "bootstrap-admin",
    AdminOrgID:               "system",
    AdminEmail:               "admin@system.local",
    Roles:                    []string{"superadmin"},
}
```

### Ignore Routes

```go
config.IgnoreApiKeyForRoutePatterns = []string{
    "/health",
    "/version",
    "/public/.*",
}
```

## Troubleshooting

### Redis Connection Failed

```
Error: failed to connect to Redis
```

**Solution**: Ensure Redis is running:
```bash
docker-compose up -d
docker-compose ps
```

### Bootstrap Key Not Shown

```
Bootstrap not executed
```

**Solution**: This is normal if a system admin key already exists. To reset:
```bash
docker-compose down -v  # Removes Redis data
docker-compose up -d
go run main.go
```

### Authentication Failed

```
401 Unauthorized
```

**Solution**:
1. Check you're using the correct API key from bootstrap logs
2. Verify the header name matches (default: `X-API-Key`)
3. Check the API key hasn't been deleted

### CRUD Routes Not Working

```
404 Not Found
```

**Solution**: Ensure `EnableCRUD: true` in config and routes are registered:
```go
config.EnableCRUD = true
apikeys.RegisterCRUDRoutes(manager, app)
```

## Security Best Practices

### Bootstrap Mode

⚠️ **Bootstrap mode logs API keys in plain text!**

1. Only use bootstrap for initial setup
2. Disable bootstrap in production: `config.EnableBootstrap = false`
3. Delete or secure logs after bootstrap
4. Create production keys via API after bootstrap

### API Key Storage

- Store API keys securely (environment variables, secrets manager)
- Never commit API keys to version control
- Rotate keys regularly
- Use different keys for different environments

### Production Deployment

1. **Disable bootstrap**: `config.EnableBootstrap = false`
2. **Use TLS**: Always use HTTPS in production
3. **Rate limiting**: Enable rate limiting when available
4. **Monitoring**: Monitor authentication failures
5. **Logging**: Secure logs containing bootstrap keys

## Cleanup

Stop and remove all containers and data:

```bash
docker-compose down -v
```

## Next Steps

- Read the main [README.md](../README.md) for detailed documentation
- Check [CODE_RULES.md](../CODE_RULES.md) for development standards
- Review API documentation in the source code
- Explore test files for more usage patterns

## Support

- GitHub Issues: https://github.com/itsatony/go-apikeys/issues
- Documentation: See main README.md
