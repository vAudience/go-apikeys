// Package apikeys provides API key authentication and management middleware for Go applications.
package apikeys

import (
	"context"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
)

// APIKeyManager orchestrates API key authentication and management.
// This is the main entry point for the middleware.
type APIKeyManager struct {
	config    *Config
	logger    *zap.Logger
	service   *APIKeyService
	limiter   RateLimiterInterface
	framework HTTPFramework
}

// New creates a new API key manager with the given configuration.
// This validates the configuration and initializes all components.
func New(config *Config) (*APIKeyManager, error) {
	// Apply defaults
	config.ApplyDefaults()

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Create repository adapter
	repo, err := NewDataRepositoryAdapter(config.Repository)
	if err != nil {
		return nil, err
	}

	// Create service layer
	service, err := NewAPIKeyService(repo, config.Logger, config.ApiKeyPrefix, config.ApiKeyLength)
	if err != nil {
		return nil, err
	}

	// Create stub rate limiter if enabled
	// TODO: Replace with production rate limiter when external package is ready
	var limiter RateLimiterInterface
	if config.EnableRateLimit {
		limiter = NewStubRateLimiter(config.Logger)
	}

	manager := &APIKeyManager{
		config:    config,
		logger:    config.Logger.Named(CLASS_APIKEY_MANAGER),
		service:   service,
		limiter:   limiter,
		framework: config.Framework,
	}

	// Log version information
	LogVersionInfo(manager.logger)

	manager.logger.Info("API key manager created",
		zap.String("version", GetProjectVersion()),
		zap.String("prefix", config.ApiKeyPrefix),
		zap.Int("key_length", config.ApiKeyLength),
		zap.Bool("crud_enabled", config.EnableCRUD),
		zap.Bool("rate_limit_enabled", config.EnableRateLimit),
		zap.Bool("bootstrap_enabled", config.EnableBootstrap))

	// Run bootstrap if enabled
	if config.EnableBootstrap {
		bootstrapService := NewBootstrapService(service, config.BootstrapConfig, config.Logger)
		_, err := bootstrapService.Bootstrap(context.Background())
		if err != nil {
			// Log error but don't fail - bootstrap may not be needed
			manager.logger.Debug("Bootstrap not executed",
				zap.Error(err))
		}
	}

	return manager, nil
}

func (m *APIKeyManager) UserID(c interface{}) string {
	apiKeyInfo := m.Get(c)
	if apiKeyInfo == nil {
		return ""
	}
	return apiKeyInfo.UserID
}

func (m *APIKeyManager) APIKey(c interface{}) string {
	apiKeyInfo := m.Get(c)
	if apiKeyInfo == nil {
		return ""
	}
	return apiKeyInfo.APIKeyHash
}

func (m *APIKeyManager) OrgID(c interface{}) string {
	apiKeyInfo := m.Get(c)
	if apiKeyInfo == nil {
		return ""
	}
	return apiKeyInfo.OrgID
}

func (m *APIKeyManager) Name(c interface{}) string {
	apiKeyInfo := m.Get(c)
	if apiKeyInfo == nil {
		return ""
	}
	return apiKeyInfo.Name
}

func (m *APIKeyManager) Email(c interface{}) string {
	apiKeyInfo := m.Get(c)
	if apiKeyInfo == nil {
		return ""
	}
	return apiKeyInfo.Email
}

func (m *APIKeyManager) Metadata(c interface{}) map[string]any {
	apiKeyInfo := m.Get(c)
	if apiKeyInfo == nil {
		return nil
	}
	return apiKeyInfo.Metadata
}

// Get retrieves the API key information from the request context.
// Returns nil if no API key information is found in the context.
func (m *APIKeyManager) Get(c interface{}) *APIKeyInfo {
	// Determine which key to use based on framework type
	// Fiber uses string keys (LOCALS_KEY_APIKEYS), stdlib uses typed keys (contextKeyAPIKeyInfo)
	var value interface{}
	switch m.framework.(type) {
	case *FiberFramework:
		// Fiber uses Locals() which requires string keys
		value = m.framework.GetContextValue(c, LOCALS_KEY_APIKEYS)
	default:
		// Stdlib and Gorilla Mux use context.Context with typed keys
		value = m.framework.GetContextValue(c, contextKeyAPIKeyInfo)
	}

	if value == nil {
		return nil
	}
	apiKeyInfo, ok := value.(*APIKeyInfo)
	if !ok {
		m.logger.Error("API key information not found in context",
			zap.Any("value", value))
		return nil
	}
	return apiKeyInfo
}

// FiberMiddleware returns a type-safe Fiber middleware handler.
// This is the recommended way to use the middleware with Fiber v2.
//
// Usage:
//   app := fiber.New()
//   app.Use(manager.FiberMiddleware())
func (m *APIKeyManager) FiberMiddleware() fiber.Handler {
	if _, ok := m.framework.(*FiberFramework); !ok {
		m.logger.Warn("FiberMiddleware called but framework is not Fiber")
	}
	return m.fiberMiddleware()
}

// StdlibMiddleware returns a type-safe stdlib middleware handler.
// This works with net/http and Gorilla Mux.
//
// Usage:
//   // With net/http:
//   http.Handle("/", manager.StdlibMiddleware()(myHandler))
//
//   // With Gorilla Mux:
//   r := mux.NewRouter()
//   r.Use(mux.MiddlewareFunc(func(next http.Handler) http.Handler {
//       return manager.StdlibMiddleware()(next)
//   }))
func (m *APIKeyManager) StdlibMiddleware() func(http.Handler) http.Handler {
	return m.standardMiddleware()
}

// Middleware returns a middleware handler for the configured framework.
//
// Deprecated: Use FiberMiddleware() or StdlibMiddleware() instead for type safety.
// This method returns interface{} which requires type assertion and is error-prone.
//
// Migration path:
//   // Old (requires type assertion):
//   app.Use(manager.Middleware().(fiber.Handler))
//
//   // New (type-safe):
//   app.Use(manager.FiberMiddleware())
func (m *APIKeyManager) Middleware() interface{} {
	switch m.framework.(type) {
	case *FiberFramework:
		return m.fiberMiddleware()
	default:
		return m.standardMiddleware()
	}
}

// CreateAPIKey creates a new API key. Delegates to the service layer.
func (m *APIKeyManager) CreateAPIKey(ctx context.Context, apiKeyInfo *APIKeyInfo) (*APIKeyInfo, error) {
	return m.service.CreateAPIKey(ctx, apiKeyInfo)
}

// GetAPIKeyInfo retrieves an API key by its plain key or hash. Delegates to the service layer.
func (m *APIKeyManager) GetAPIKeyInfo(ctx context.Context, apiKeyOrHash string) (*APIKeyInfo, error) {
	return m.service.GetAPIKeyInfo(ctx, apiKeyOrHash)
}

// SetAPIKeyInfo updates an API key. Delegates to the service layer.
//
// Deprecated: Use UpdateAPIKey instead. This method is maintained for backward
// compatibility but will be removed in v2.0.0.
//
// Migration path:
//   // Old (deprecated):
//   err := manager.SetAPIKeyInfo(ctx, apiKeyInfo)
//
//   // New (recommended):
//   err := manager.UpdateAPIKey(ctx, apiKeyInfo)
func (m *APIKeyManager) SetAPIKeyInfo(ctx context.Context, apiKeyInfo *APIKeyInfo) error {
	return m.service.UpdateAPIKey(ctx, apiKeyInfo)
}

// UpdateAPIKey updates an API key. Delegates to the service layer.
func (m *APIKeyManager) UpdateAPIKey(ctx context.Context, apiKeyInfo *APIKeyInfo) error {
	return m.service.UpdateAPIKey(ctx, apiKeyInfo)
}

// DeleteAPIKey deletes an API key. Delegates to the service layer.
func (m *APIKeyManager) DeleteAPIKey(ctx context.Context, apiKeyOrHash string) error {
	return m.service.DeleteAPIKey(ctx, apiKeyOrHash)
}

// SearchAPIKeys searches for API keys with pagination. Delegates to the service layer.
func (m *APIKeyManager) SearchAPIKeys(ctx context.Context, offset, limit int) ([]*APIKeyInfo, int, error) {
	return m.service.SearchAPIKeys(ctx, nil, offset, limit)
}
