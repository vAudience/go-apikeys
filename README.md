# go-apikeys

go-apikeys is a flexible middleware package for Go web applications that handles API key management, rate limiting, and CRUD operations for REST APIs. It now supports multiple web frameworks and provides a convenient way to authenticate and authorize API requests based on API keys stored in a flexible repository.

## Version

v0.4.0

## Features

- Support for multiple web frameworks (including Fiber and Gorilla Mux)
- Flexible repository backend using go-datarepository
- API key management with CRUD operations
- Rate limiting with configurable rules
- Customizable logging
- Swagger annotations for API documentation
- Backwards compatibility with previous versions (see migration guide)

## Installation

```bash
go get -u github.com/vaudience/go-apikeys@v0.4.0
```

## Usage

Here's an example of how to use the go-apikeys package:

```go
package main

import (
    "time"

    "github.com/gofiber/fiber/v2"
    "github.com/itsatony/go-datarepository"
    "github.com/vaudience/go-apikeys"
)

func main() {
    app := fiber.New()

    repo, err := datarepository.CreateDataRepository("redis", datarepository.RedisConfig{
        ConnectionString: "localhost:6379",
    })
    if err != nil {
        log.Fatal(err)
    }

    rateLimitRules := []apikeys.RateLimitRule{
        {
            Path:     "/api/v1/.*",
            Timespan: 1 * time.Minute,
            Limit:    100,
            ApplyTo:  []apikeys.RateLimitRuleTarget{apikeys.RateLimitRuleTargetAPIKey},
        },
    }

    apiKeysConfig := &apikeys.Config{
        HeaderKey:       "X-API-Key",
        ApiKeyLength:    32,
        ApiKeyPrefix:    "gak_",
        Repository:      repo,
        SystemAPIKey:    "your-system-api-key",
        EnableCRUD:      true,
        EnableRateLimit: true,
        RateLimitRules:  rateLimitRules,
        Framework:       &apikeys.FiberFramework{},
    }

    apikeysManager, err := apikeys.New(apiKeysConfig)
    if err != nil {
        log.Fatal(err)
    }

    app.Use(apikeysManager.Middleware())

    // Register CRUD routes
    apikeys.RegisterCRUDRoutes(app.Group("/api"), apikeysManager)

    app.Get("/protected", func(c *fiber.Ctx) error {
        apiKeyInfo := apikeysManager.Get(c)
        return c.SendString("Protected route accessed by user: " + apiKeyInfo.UserID)
    })

    app.Listen(":8080")
}
```

## Configuration

The `Config` struct allows you to customize the behavior of go-apikeys:

- `HeaderKey`: The name of the header key used to retrieve the API key from the request.
- `ApiKeyLength`: The length of generated API keys.
- `ApiKeyPrefix`: The prefix for generated API keys.
- `Repository`: An implementation of `datarepository.DataRepository` for storing API keys.
- `SystemAPIKey`: An optional system API key for administrative operations.
- `EnableCRUD`: Enable or disable CRUD endpoints for API key management.
- `EnableRateLimit`: Enable or disable rate limiting.
- `RateLimitRules`: An array of `RateLimitRule` structs specifying the rate limit rules.
- `Framework`: An implementation of the `HTTPFramework` interface for your chosen web framework.

## API Documentation

go-apikeys now includes Swagger annotations for all CRUD endpoints. To generate API documentation:

1. Install swaggo: `go get -u github.com/swaggo/swag/cmd/swag`
2. Run `swag init` in your project root
3. Serve the generated Swagger UI in your application

## Migration Guide: v0.3.x to v0.4.0

### Key Changes

1. Support for multiple web frameworks
2. Migration from direct Redis usage to go-datarepository
3. Updated configuration structure
4. New abstraction layer for HTTP frameworks

### Step-by-Step Migration

1. Update your imports:
   ```go
   import (
       "github.com/vaudience/go-apikeys"
       "github.com/itsatony/go-datarepository"
   )
   ```

2. Update your configuration:
   ```go
   repo, err := datarepository.CreateDataRepository("redis", datarepository.RedisConfig{
       ConnectionString: "localhost:6379",
   })
   if err != nil {
       log.Fatal(err)
   }

   apiKeysConfig := &apikeys.Config{
       // ... other fields ...
       Repository: repo,
       Framework:  &apikeys.FiberFramework{}, // or &apikeys.GorillaMuxFramework{} for Gorilla Mux
   }
   ```

3. Update CRUD operations:
   - If you were using CRUD operations directly, they are now methods on the `APIKeyManager`:
     ```go
     // Old
     apiKeyInfo, err := apikeyManager.repo.GetAPIKeyInfo(apiKey, "")

     // New
     apiKeyInfo, err := apikeyManager.GetAPIKeyInfo(context.Background(), apiKey)
     ```

4. Update rate limiting:
   - Rate limiting now uses the go-datarepository package. The `RateLimiter` struct has been updated accordingly.

5. Update error handling:
   - Use the new error types from go-datarepository:
     ```go
     if datarepository.IsNotFoundError(err) {
         // handle not found error
     }
     ```

6. Update middleware usage:
   - The `Middleware()` function now returns an `interface{}` that needs to be adapted to your web framework.

7. Update route registration:
   - Use the new `RegisterCRUDRoutes` function to register CRUD routes:
     ```go
     apikeys.RegisterCRUDRoutes(app.Group("/api"), apikeysManager)
     ```

### Breaking Changes

1. The `RedisClient` field in the `Config` struct has been removed and replaced with `Repository`.
2. Direct Redis operations are no longer available. Use the provided methods or interact with the `Repository` instead.
3. The `Framework` field in the `Config` struct is now required.

If you encounter any issues during migration, please refer to the updated documentation or open an issue on the GitHub repository.

## Contributing

Contributions to the go-apikeys package are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
