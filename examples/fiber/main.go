package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/itsatony/go-datarepository"
	apikeys "github.com/vaudience/go-apikeys/v2"
	"go.uber.org/zap"
)

func main() {
	// Initialize logger
	zapLogger, err := zap.NewDevelopment()
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}
	defer zapLogger.Sync()

	// Connect to Redis
	redisRepo, err := connectToRedis(zapLogger)
	if err != nil {
		zapLogger.Fatal("Failed to connect to Redis", zap.Error(err))
	}

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName:               "go-apikeys Fiber Example",
		DisableStartupMessage: false,
		ErrorHandler:          customErrorHandler,
	})

	// Add middleware
	app.Use(recover.New())
	app.Use(logger.New())
	app.Use(cors.New())

	// Create API key manager configuration
	config := &apikeys.Config{
		Repository:   redisRepo,
		Framework:    &apikeys.FiberFramework{},
		HeaderKey:    "X-API-Key",
		ApiKeyPrefix: "gak_",
		ApiKeyLength: 32,
		Logger:       zapLogger,
		EnableCRUD:   true,

		// Ignore API key check for public routes
		IgnoreApiKeyForRoutePatterns: []string{
			"/health",
			"/version",
			"/public/.*",
		},

		// Enable bootstrap for initial setup
		// WARNING: This logs API keys in plain text!
		EnableBootstrap: true,
		BootstrapConfig: &apikeys.BootstrapConfig{
			// REQUIRED: Explicit acknowledgment of security risks
			IUnderstandSecurityRisks: true,
			AdminUserID:              "bootstrap-admin",
			AdminOrgID:               "system",
			AdminEmail:               "admin@system.local",
			Roles:                    []string{"superadmin"},
			RecoveryPath:             "", // Set to save recovery file (e.g., "./.bootstrap-key")
		},
	}

	// Create API key manager
	manager, err := apikeys.New(config)
	if err != nil {
		zapLogger.Fatal("Failed to create API key manager", zap.Error(err))
	}

	// Public routes (no authentication)
	app.Get("/health", handleHealth)
	app.Get("/version", handleVersion)
	app.Get("/public/info", handlePublicInfo)

	// Protected routes (require API key)
	// Apply authentication middleware globally
	app.Use(manager.FiberMiddleware())

	// Register CRUD routes for API key management
	// Routes: POST /apikeys, GET /apikeys, GET /apikeys/:id, PUT /apikeys/:id, DELETE /apikeys/:id
	apikeys.RegisterCRUDRoutes(app, manager)

	// Example protected API routes
	api := app.Group("/api")
	api.Get("/hello", handleHello(manager))
	api.Get("/me", handleMe(manager))
	api.Post("/data", handleCreateData(manager))

	// Start server with graceful shutdown
	go func() {
		if err := app.Listen(":8080"); err != nil {
			zapLogger.Fatal("Failed to start server", zap.Error(err))
		}
	}()

	zapLogger.Info("Server started",
		zap.String("address", "http://localhost:8080"),
		zap.String("health", "http://localhost:8080/health"),
		zap.String("api", "http://localhost:8080/api/hello"))

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	zapLogger.Info("Shutting down server...")
	if err := app.ShutdownWithTimeout(10 * time.Second); err != nil {
		zapLogger.Error("Server forced to shutdown", zap.Error(err))
	}

	zapLogger.Info("Server stopped")
}

// connectToRedis creates a Redis repository connection
func connectToRedis(logger *zap.Logger) (datarepository.DataRepository, error) {
	// Get Redis connection string from environment or use default
	// Format: "mode;type;;;;;;database;host:port"
	redisConnStr := os.Getenv("REDIS_CONN")
	if redisConnStr == "" {
		redisConnStr = "single;redis_stack;;;;;;0;localhost:6379"
	}

	logger.Info("Connecting to Redis",
		zap.String("connection", redisConnStr))

	// Create Redis repository using go-datarepository
	repo, err := datarepository.CreateDataRepository("redis",
		datarepository.NewRedisConfig(
			redisConnStr,
			"go_apikeys",        // Key prefix for all API keys
			":",                 // Key delimiter
			func(level, msg string) { // Logger function
				switch level {
				case "error":
					logger.Error(msg)
				case "warn":
					logger.Warn(msg)
				default:
					logger.Info(msg)
				}
			},
		))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	logger.Info("Connected to Redis successfully")
	return repo, nil
}

// customErrorHandler handles Fiber errors
func customErrorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	message := "Internal Server Error"

	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
		message = e.Message
	}

	return c.Status(code).JSON(fiber.Map{
		"error":   message,
		"code":    code,
		"success": false,
	})
}

// Handler: Health check (public)
func handleHealth(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status":  "ok",
		"service": "go-apikeys-fiber-example",
		"time":    time.Now().Format(time.RFC3339),
	})
}

// Handler: Version info (public)
func handleVersion(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"version":    "1.0.0",
		"go_apikeys": apikeys.GetProjectVersion(),
		"framework":  "fiber",
	})
}

// Handler: Public info (public)
func handlePublicInfo(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"message": "This is a public endpoint, no authentication required",
		"docs":    "See /api/* for authenticated endpoints",
	})
}

// Handler: Hello (protected)
func handleHello(manager *apikeys.APIKeyManager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get API key info from context
		info := manager.Get(c)
		if info == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "API key information not found",
			})
		}

		return c.JSON(fiber.Map{
			"message": fmt.Sprintf("Hello, %s!", info.Name),
			"user_id": info.UserID,
			"org_id":  info.OrgID,
			"roles":   info.Roles,
		})
	}
}

// Handler: Get current user info (protected)
func handleMe(manager *apikeys.APIKeyManager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Alternative: Use convenience methods
		userID := manager.UserID(c)
		orgID := manager.OrgID(c)
		name := manager.Name(c)
		email := manager.Email(c)
		metadata := manager.Metadata(c)

		return c.JSON(fiber.Map{
			"user_id":  userID,
			"org_id":   orgID,
			"name":     name,
			"email":    email,
			"metadata": metadata,
		})
	}
}

// Handler: Create data (protected)
func handleCreateData(manager *apikeys.APIKeyManager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Parse request body
		var req struct {
			Data string `json:"data"`
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request body",
			})
		}

		// Get user info for audit
		userID := manager.UserID(c)
		orgID := manager.OrgID(c)

		// Simulate creating data
		result := fiber.Map{
			"id":         "data_123",
			"data":       req.Data,
			"created_by": userID,
			"org_id":     orgID,
			"created_at": time.Now().Format(time.RFC3339),
		}

		return c.Status(fiber.StatusCreated).JSON(result)
	}
}
