# Go-APIKeys Package Summary

## Overview
`go-apikeys` is a middleware package for Go web applications that provides API key management, rate limiting, and CRUD operations for REST APIs. Current version: v0.4.5.

## Key Features
- Multi-framework support (Fiber, Gorilla Mux)
- API key authentication and authorization
- Rate limiting with configurable rules
- CRUD operations for API key management
- Flexible data storage via go-datarepository
- Swagger annotations for API documentation

## Installation
```bash
go get -u github.com/vaudience/go-apikeys@v0.4.5
```

## Core Components

### APIKeyManager
The central component that handles API key validation, rate limiting, and management.

### Configuration
```go
import (
    "github.com/vaudience/go-apikeys"
    "github.com/itsatony/go-datarepository"
)

// Create logger function
apikeysLogger := func(logLevel string, logContent string) {
    log.Println(logLevel + ": " + logContent)
}

// Setup repository
config := datarepository.NewRedisConfig(
    "single;redis_stack;;;;;;0;localhost:6379",
    "appName_apikeys",
    ":",
    apikeysLogger,
)
repo, err := datarepository.CreateDataRepository("redis", config)
if err != nil {
    log.Fatal(err)
}

// Define rate limit rules
rateLimitRules := []apikeys.RateLimitRule{
    {
        Path:     "/api/v1/.*",
        Timespan: 1 * time.Minute,
        Limit:    100,
        ApplyTo:  []apikeys.RateLimitRuleTarget{apikeys.RateLimitRuleTargetAPIKey},
    },
}

// Create framework implementation
framework := &apikeys.FiberFramework{} // or &apikeys.GorillaMuxFramework{}

// Configure API Keys manager
apiKeysConfig := &apikeys.Config{
    HeaderKey:       "X-API-Key",      // HTTP header name for API key
    ApiKeyLength:    32,               // Length of generated API keys
    ApiKeyPrefix:    "gak_",           // Prefix for API keys
    Repository:      repo,             // Data repository
    SystemAPIKey:    "system-api-key", // System admin key
    EnableCRUD:      true,             // Enable CRUD endpoints
    EnableRateLimit: true,             // Enable rate limiting
    RateLimitRules:  rateLimitRules,   // Rate limit configuration
    Framework:       framework,        // Web framework implementation
}

// Create API Keys manager
apikeysManager, err := apikeys.New(apiKeysConfig)
if err != nil {
    log.Fatal(err)
}
```

## Framework Integration

### Fiber
```go
import (
    "github.com/gofiber/fiber/v2"
    "github.com/vaudience/go-apikeys"
)

app := fiber.New()
fiberFramework := &apikeys.FiberFramework{}

// Create and configure API keys manager
apiKeysConfig := &apikeys.Config{
    // Configuration as shown above
    Framework: fiberFramework,
}
apikeysManager, err := apikeys.New(apiKeysConfig)
if err != nil {
    log.Fatal(err)
}

// Apply middleware
app.Use(fiberFramework.FiberMiddleware(apikeysManager))

// Register CRUD routes (optional)
apikeys.RegisterCRUDRoutes(app.Group("/api"), apikeysManager)

// Protected route example
app.Get("/protected", func(c *fiber.Ctx) error {
    // Get API key info from the context
    apiKeyInfo := apikeysManager.Get(c)
    
    // Use API key info
    return c.SendString("Protected route accessed by user: " + apiKeyInfo.UserID)
})

app.Listen(":8080")
```

### Gorilla Mux
```go
import (
    "github.com/gorilla/mux"
    "github.com/vaudience/go-apikeys"
)

router := mux.NewRouter()
muxFramework := &apikeys.GorillaMuxFramework{}

// Create and configure API keys manager
apiKeysConfig := &apikeys.Config{
    // Configuration as shown above
    Framework: muxFramework,
}
apikeysManager, err := apikeys.New(apiKeysConfig)
if err != nil {
    log.Fatal(err)
}

// Apply middleware
router.Use(muxFramework.MuxMiddleware(apikeysManager))

// Register CRUD routes (optional)
apikeys.RegisterCRUDRoutes(router.PathPrefix("/api").Subrouter(), apikeysManager)

// Protected route example
router.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
    // Get API key info from the request
    apiKeyInfo := apikeysManager.Get(r)
    
    // Use API key info
    w.Write([]byte("Protected route accessed by user: " + apiKeyInfo.UserID))
})

http.ListenAndServe(":8080", router)
```

## Data Types

### Config
```go
type Config struct {
    HeaderKey       string                       // HTTP header name for API key
    ApiKeyLength    int                          // Length of generated API keys
    ApiKeyPrefix    string                       // Prefix for API keys
    Repository      datarepository.DataRepository // Storage for API keys
    SystemAPIKey    string                       // System admin key
    EnableCRUD      bool                         // Enable CRUD endpoints
    EnableRateLimit bool                         // Enable rate limiting
    RateLimitRules  []RateLimitRule              // Rate limit configuration
    Framework       HTTPFramework                // Web framework implementation
}
```

### APIKeyInfo
```go
type APIKeyInfo struct {
    ID        string    // Unique identifier
    Key       string    // API key
    UserID    string    // Associated user ID
    Name      string    // Name of the API key
    Roles     []string  // User roles
    CreatedAt time.Time // Creation timestamp
    ExpiresAt time.Time // Expiration timestamp (optional)
    Metadata  map[string]interface{} // Additional custom data
    Active    bool      // Whether the key is active
}
```

### RateLimitRule
```go
type RateLimitRule struct {
    Path     string               // Path pattern (regex)
    Timespan time.Duration        // Time window
    Limit    int                  // Request limit within timespan
    ApplyTo  []RateLimitRuleTarget // What to apply limit to
}
```

### RateLimitRuleTarget
```go
type RateLimitRuleTarget string

const (
    RateLimitRuleTargetAPIKey RateLimitRuleTarget = "apikey"
    RateLimitRuleTargetIP     RateLimitRuleTarget = "ip"
    RateLimitRuleTargetUserID RateLimitRuleTarget = "userid"
)
```

### HTTPFramework
Interface that must be implemented for framework integration.
```go
type HTTPFramework interface {
    // Methods that need implementation for each framework
}
```

## API Endpoints (when CRUD is enabled)

### Create API Key
- **Endpoint**: `POST /apikeys`
- **Description**: Creates a new API key
- **Request Body**:
  ```json
  {
    "user_id": "user123",
    "name": "My API Key",
    "roles": ["admin", "user"],
    "expires_at": "2023-12-31T23:59:59Z",
    "metadata": {
      "app": "my-app",
      "environment": "production"
    }
  }
  ```
- **Response**: The created API key object with key value

### Get API Key
- **Endpoint**: `GET /apikeys/{key}`
- **Description**: Retrieves information about an API key
- **Response**: API key information without the key value

### List API Keys
- **Endpoint**: `GET /apikeys`
- **Description**: Lists all API keys
- **Query Parameters**:
  - `user_id`: Filter by user ID
  - `role`: Filter by role
  - `page`: Page number for pagination
  - `limit`: Number of items per page
- **Response**: List of API key information objects

### Update API Key
- **Endpoint**: `PUT /apikeys/{key}`
- **Description**: Updates an existing API key
- **Request Body**:
  ```json
  {
    "name": "Updated API Key",
    "roles": ["admin"],
    "active": true,
    "metadata": {
      "updated": true
    }
  }
  ```
- **Response**: Updated API key information

### Delete API Key
- **Endpoint**: `DELETE /apikeys/{key}`
- **Description**: Deletes an API key
- **Response**: Success message

## Rate Limiting

### Configuration
Rate limiting is configured using `RateLimitRule` structs:

```go
rateLimitRules := []apikeys.RateLimitRule{
    {
        Path:     "/api/v1/.*",         // Regex pattern matching path
        Timespan: 1 * time.Minute,      // Time window
        Limit:    100,                  // Max requests in window
        ApplyTo:  []apikeys.RateLimitRuleTarget{
            apikeys.RateLimitRuleTargetAPIKey,  // Limit per API key
            apikeys.RateLimitRuleTargetIP,      // Limit per IP address
        },
    },
    {
        Path:     "/api/v1/limited/.*", // Another path
        Timespan: 1 * time.Hour,
        Limit:    10,
        ApplyTo:  []apikeys.RateLimitRuleTarget{
            apikeys.RateLimitRuleTargetUserID,  // Limit per user ID
        },
    },
}
```

### Rate Limit Response
When a request exceeds the rate limit, the API responds with:
- Status code: 429 Too Many Requests
- Headers:
  - `X-RateLimit-Limit`: The rate limit ceiling
  - `X-RateLimit-Remaining`: The number of requests left for the time window
  - `X-RateLimit-Reset`: The remaining time (in seconds) until the rate limit resets

## Core Methods

### Create API Key
```go
apiKeyInfo, apiKey, err := apikeysManager.CreateAPIKey(ctx, userID, name, roles, expiresAt, metadata)
```

### Validate API Key
```go
apiKeyInfo, err := apikeysManager.ValidateAPIKey(ctx, apiKey)
```

### Get API Key Info
```go
apiKeyInfo, err := apikeysManager.GetAPIKeyInfo(ctx, apiKey)
```

### Update API Key
```go
apiKeyInfo, err := apikeysManager.UpdateAPIKey(ctx, apiKey, name, roles, active, metadata)
```

### Delete API Key
```go
err := apikeysManager.DeleteAPIKey(ctx, apiKey)
```

### List API Keys
```go
apiKeys, totalCount, err := apikeysManager.ListAPIKeys(ctx, userID, role, page, limit)
```

### Get from Context/Request
```go
// Get API key info from context/request
apiKeyInfo := apikeysManager.Get(c) // Fiber context or http.Request
```

## Best Practices

1. **Security**: 
   - Use HTTPS for all API endpoints
   - Implement proper role-based access control
   - Set reasonable expiration times for API keys

2. **Rate Limiting**:
   - Configure appropriate rate limits based on endpoint sensitivity
   - Apply multiple rate limit targets for better protection
   - Consider different limits for different user roles

3. **API Key Management**:
   - Use meaningful names for API keys
   - Store metadata to track key usage and purpose
   - Regularly audit and rotate API keys

4. **Error Handling**:
   - Handle rate limit errors gracefully in your client applications
   - Provide clear error messages when API key validation fails

5. **Repository Configuration**:
   - Use a reliable storage backend for the repository
   - Configure proper persistence for API key data
   - Consider backup and recovery strategies

## Common Patterns

### Role-Based Access Control
```go
app.Get("/admin-only", func(c *fiber.Ctx) error {
    apiKeyInfo := apikeysManager.Get(c)
    
    // Check if user has admin role
    hasAdminRole := false
    for _, role := range apiKeyInfo.Roles {
        if role == "admin" {
            hasAdminRole = true
            break
        }
    }
    
    if !hasAdminRole {
        return c.Status(403).SendString("Forbidden")
    }
    
    return c.SendString("Admin area")
})
```

### Custom Metadata Usage
```go
app.Get("/custom-endpoint", func(c *fiber.Ctx) error {
    apiKeyInfo := apikeysManager.Get(c)
    
    // Access custom metadata
    appName, ok := apiKeyInfo.Metadata["app"].(string)
    if !ok {
        appName = "unknown"
    }
    
    return c.SendString("Hello from app: " + appName)
})
```

### System API Key Usage
```go
// System operations using system API key
req.Header.Set("X-API-Key", systemAPIKey)
```

### API Key Rotation
```go
// Create new API key
newApiKeyInfo, newApiKey, _ := apikeysManager.CreateAPIKey(
    ctx, userID, "Rotated Key", roles, expiresAt, metadata,
)

// Use new key in your applications

// Delete old key after transition period
apikeysManager.DeleteAPIKey(ctx, oldApiKey)
```
