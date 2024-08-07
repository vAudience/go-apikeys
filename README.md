# go-apikeys

go-apikeys is a middleware package for the Fiber web framework that handles API key management, rate limiting, and CRUD operations for REST APIs. It provides a convenient way to authenticate and authorize API requests based on API keys stored in a Redis repository.

## Installation

```bash
go get -u github.com/vaudience/go-apikeys@v0.3.7
```

## Version

v0.3.7

## TODO

- Add tests

## Features

- Initialization via a verbose configuration
- Reading API key from request headers based on configuration
- Retrieving API key information from a Redis repository
- Storing API key information in `fiber.Ctx.Locals` for easy access
- Support for a system API key that can be added/overridden via configuration
- APIKeys are bcrypt-hashed and stored in Redis
- Optional CRUD endpoints for API key management (accessible only with a special "systemadmin" API key)
- Rate limiting using Redis with configurable time spans, limits, and path matching
- Ability to apply rate limits based on API key, user ID, or organization ID
- Helper functions to easily access API key information within Fiber handlers
- Versioned search index for efficient searching of API keys
- Helper methods to list all index versions and delete old index versions
- Method to retrieve the current rate limit value for a specific rule and API key

## Usage

Here's an example of how to use the go-apikeys package in your Fiber application:

```go
package main

import (
    "time"

    "github.com/gofiber/fiber/v2"
    "github.com/redis/go-redis/v9"
    "github.com/vaudience/go-apikeys"
)

func main() {
    app := fiber.New()

    redisClient := redis.NewUniversalClient(&redis.UniversalOptions{
        Addr: "localhost:6379",
    })

    rateLimitRules := []apikeys.RateLimitRule{
        {
            Path:     "/api/v1/.*",
            Timespan: 1 * time.Minute,
            Limit:    100,
            ApplyTo:  []apikeys.RateLimitRuleTarget{apikeys.RateLimitRuleTargetAPIKey},
        },
        {
            Path:     "/api/v1/premium/.*",
            Timespan: 1 * time.Hour,
            Limit:    1000,
            ApplyTo:  []apikeys.RateLimitRuleTarget{apikeys.RateLimitRuleTargetUserID, apikeys.RateLimitRuleTargetOrgID}, 
        },
    }

    apiKeysConfig := &apikeys.Config{
        HeaderKey:       "X-API-Key",
        ApiKeyLength:    32,
        ApiKeyPrefix:   "gak_",
        RedisClient:     redisClient,
        SystemAPIKey:    "your-system-api-key",
        EnableCRUD:      true,
        CRUDGroup:       app.Group("/api/keys"),
        EnableRateLimit: true,
        RateLimitRules:  rateLimitRules,
    }

    // instantiate your apikeys manager
    apikeysManager, err := apikeys.New(apiKeysConfig)
    if err != nil {
      nuts.L.Errorf("Error creating apikeys middleware: %v", err)
      return nil
    }

    err = apikeysManager.Repository().LoadAllKeysFromJSONFile("apikeys.json")
    if err != nil {
        log.Fatal(err)
    }

    app.Use(apikeysManager.Middleware())

    app.Get("/protected", func(c *fiber.Ctx) error {
        userID := apikeysManager.UserID(c)
        orgID := apikeysManager.OrgID(c)
        metadata := apikeysManager.Metadata(c)
        allInfo := apikeysManager.Get(c)
        // Use the retrieved values in your handler logic

        return c.SendString("Protected route accessed by user: " + userID)
    })

    app.Listen(":8080")
}
```

## Configuration

The go-apikeys package is configured using the `Config` struct, which has the following fields:

- `HeaderKey`: The name of the header key used to retrieve the API key from the request (default: "X-API-Key").
- `RedisClient`: A pre-connected go-redis `UniversalClient` for storing and retrieving API key information.
- `SystemAPIKey`: An optional system API key that can be added/overridden via configuration.
- `EnableCRUD`: A boolean flag indicating whether to enable CRUD endpoints for API key management (default: false).
- `CRUDGroup`: A Fiber router group to which the CRUD endpoints will be attached (required if `EnableCRUD` is true).
- `EnableRateLimit`: A boolean flag indicating whether to enable rate limiting (default: false).
- `RateLimitRules`: An array of `RateLimitRule` structs specifying the rate limit rules.

## Repository

The go-apikeys package uses a Redis repository to store and retrieve API key information. The repository implementation is located in the `repo.go` file and satisfies the `Repository` interface.

The `APIKeyInfo` struct represents the API key information stored in the repository and has the following fields:

- `APIKey`: The API key itself.
- `APIKeyHash`: The sha3.512-hashed version of the API key.
- `APIKeyHint`: The first and last 3 characters of the API key.
- `UserID`: The ID of the user associated with the API key.
- `OrgID`: The ID of the organization associated with the API key.
- `Name`: The name of the API key.
- `Email`: The email associated with the API key.
- `Roles`: An array of roles assigned to the API key.
- `Rights`: An array of rights assigned to the API key.
- `Metadata`: A map of additional metadata associated with the API key.

## Rate Limiting

The go-apikeys package supports rate limiting using Redis with configurable time spans, limits, and path matching. The rate limiting rules are defined using the `RateLimitRule` struct, which has the following fields:

- `Path`: A regular expression pattern for matching the request path.
- `Timespan`: The time span for the rate limit window.
- `Limit`: The maximum number of requests allowed within the time span.
- `ApplyTo`: An array of strings specifying the attributes to apply the rate limit to (e.g., "apikey", "userID", "orgID").

Rate limits can be applied based on the API key, user ID, or organization ID. Multiple rate limit rules can be defined, and each rule is evaluated independently.

## CRUD Endpoints

If CRUD endpoints are enabled, the go-apikeys package provides the following endpoints for managing API keys:

- `POST /api/keys`: Create a new API key.
- `GET /api/keys/:id`: Retrieve an API key by ID.
- `PUT /api/keys/:id`: Update an API key by ID.
- `DELETE /api/keys/:id`: Delete an API key by ID.

The actual endpoints will depend on the `CRUDGroup` specified in the configuration.

**Note:** The CRUD endpoints are protected and can only be accessed by providing a special API key with the metadata field "systemadmin" set to `true`. This ensures that only authorized users with the necessary privileges can perform these operations.

## Helper Functions

The go-apikeys package provides several helper functions to easily access API key information within your Fiber handlers:

- `Get(c *fiber.Ctx) *APIKeyInfo`: Retrieves the entire `APIKeyInfo` struct containing all the API key information.
- `UserID(c *fiber.Ctx) string`: Retrieves the user ID associated with the API key.
- `APIKey(c *fiber.Ctx) string`: Retrieves the API key itself.
- `OrgID(c *fiber.Ctx) string`: Retrieves the organization ID associated with the API key.
- `Name(c *fiber.Ctx) string`: Retrieves the name associated with the API key.
- `Email(c *fiber.Ctx) string`: Retrieves the email associated with the API key.
- `Metadata(c *fiber.Ctx) map[string]any`: Retrieves the metadata associated with the API key.

These helper functions make it convenient to access the API key information within your Fiber handlers without having to manually retrieve it from `fiber.Ctx.Locals`.

## Example JSON apikeys file

Here's an example of a JSON file (`apikeys.json`) containing API key information:

```json
{
  "system_api_key_hash": {
    "api_key": "demo_api_key",
    "api_key_hash": "system_api_key_hash",
    "api_key_hint": "sys...ash",
    "user_id": "system",
    "org_id": "system",
    "name": "System API Key",
    "email": "system@example.com",
    "roles": ["admin"],
    "rights": ["all"],
    "metadata": {
      "systemadmin": true
    }
  },
  "demo_api_key_hash": {
    "api_key": "demo_api_key",
    "api_key_hash": "demo_api_key_hash",
    "api_key_hint": "dem...ash",
    "user_id": "demo_user",
    "org_id": "demo_org",
    "name": "Demo API Key",
    "email": "demo@example.com",
    "roles": ["demo"],
    "rights": ["read"],
    "metadata": {
      "demo": true
    }
  }
}
```

In this example, the JSON file contains two API keys: a system API key and a demo API key. Each API key has various fields such as `api_key`, `user_id`, `org_id`, `name`, `email`, `roles`, `rights`, and `metadata`.

You can load the API keys from this JSON file using the `LoadAllKeysFromJSONFile` method of the Redis repository.

## Contributing

Contributions to the go-apikeys package are welcome! If you find a bug or have a feature request, please open an issue on the GitHub repository. If you'd like to contribute code, please fork the repository and submit a pull request.

## License

The go-apikeys package is open-source software licensed under the [MIT License](https://opensource.org/licenses/MIT).
