package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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

	// Create API key manager configuration
	// Note: Framework can be left nil for stdlib/Mux (defaults to GorillaMuxFramework)
	config := &apikeys.Config{
		Repository:   redisRepo,
		Framework:    nil, // Will default to GorillaMuxFramework for stdlib
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

	// Create HTTP mux
	mux := http.NewServeMux()

	// Public routes (no authentication)
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/version", handleVersion)
	mux.HandleFunc("/public/info", handlePublicInfo)

	// Protected routes with authentication middleware
	// Note: We wrap each protected handler with the middleware
	protectedMux := http.NewServeMux()

	// Example protected API routes
	protectedMux.HandleFunc("/api/hello", handleHello(manager))
	protectedMux.HandleFunc("/api/me", handleMe(manager))
	protectedMux.HandleFunc("/api/data", handleCreateData(manager))

	// CRUD routes for API key management
	// These are protected by the middleware as well
	registerCRUDRoutes(protectedMux, manager)

	// Apply authentication middleware to protected routes
	mux.Handle("/api/", manager.StdlibMiddleware()(protectedMux))
	mux.Handle("/apikeys", manager.StdlibMiddleware()(protectedMux))
	mux.Handle("/apikeys/", manager.StdlibMiddleware()(protectedMux))

	// Create server
	srv := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server
	go func() {
		zapLogger.Info("Server started",
			zap.String("address", "http://localhost:8080"),
			zap.String("health", "http://localhost:8080/health"),
			zap.String("api", "http://localhost:8080/api/hello"))

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			zapLogger.Fatal("Failed to start server", zap.Error(err))
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	zapLogger.Info("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
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

// registerCRUDRoutes manually registers CRUD routes for stdlib
// In production, you can use apikeys.RegisterCRUDRoutes if using Gorilla Mux
func registerCRUDRoutes(mux *http.ServeMux, manager *apikeys.APIKeyManager) {
	// For this example, we'll create a simple handler that delegates to the manager
	// In production with Gorilla Mux, use: apikeys.RegisterCRUDRoutes(manager, router)

	mux.HandleFunc("/apikeys", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			handleCreateAPIKey(manager)(w, r)
		case http.MethodGet:
			if r.URL.Query().Has("offset") || r.URL.Query().Has("limit") {
				handleListAPIKeys(manager)(w, r)
			} else {
				http.Error(w, "Use query parameters offset and limit to list keys", http.StatusBadRequest)
			}
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Note: For proper RESTful routes with path parameters like /apikeys/{id},
	// consider using Gorilla Mux which is fully supported by go-apikeys
}

// Handler: Create API key
func handleCreateAPIKey(manager *apikeys.APIKeyManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var info apikeys.APIKeyInfo
		if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]string{
				"error": "Invalid request body",
			})
			return
		}

		created, err := manager.CreateAPIKey(r.Context(), &info)
		if err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]string{
				"error": err.Error(),
			})
			return
		}

		respondJSON(w, http.StatusCreated, created)
	}
}

// Handler: List API keys
func handleListAPIKeys(manager *apikeys.APIKeyManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse query parameters
		offset := 0
		limit := 10
		fmt.Sscanf(r.URL.Query().Get("offset"), "%d", &offset)
		fmt.Sscanf(r.URL.Query().Get("limit"), "%d", &limit)

		keys, total, err := manager.SearchAPIKeys(r.Context(), offset, limit)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{
				"error": err.Error(),
			})
			return
		}

		respondJSON(w, http.StatusOK, map[string]interface{}{
			"keys":   keys,
			"total":  total,
			"offset": offset,
			"limit":  limit,
		})
	}
}

// Handler: Health check (public)
func handleHealth(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": "go-apikeys-stdlib-example",
		"time":    time.Now().Format(time.RFC3339),
	})
}

// Handler: Version info (public)
func handleVersion(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{
		"version":    "1.0.0",
		"go_apikeys": apikeys.GetProjectVersion(),
		"framework":  "stdlib",
	})
}

// Handler: Public info (public)
func handlePublicInfo(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{
		"message": "This is a public endpoint, no authentication required",
		"docs":    "See /api/* for authenticated endpoints",
	})
}

// Handler: Hello (protected)
func handleHello(manager *apikeys.APIKeyManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get API key info from context
		info := manager.Get(r)
		if info == nil {
			respondJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "API key information not found",
			})
			return
		}

		respondJSON(w, http.StatusOK, map[string]interface{}{
			"message": fmt.Sprintf("Hello, %s!", info.Name),
			"user_id": info.UserID,
			"org_id":  info.OrgID,
			"roles":   info.Roles,
		})
	}
}

// Handler: Get current user info (protected)
func handleMe(manager *apikeys.APIKeyManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Alternative: Use convenience methods
		userID := manager.UserID(r)
		orgID := manager.OrgID(r)
		name := manager.Name(r)
		email := manager.Email(r)
		metadata := manager.Metadata(r)

		respondJSON(w, http.StatusOK, map[string]interface{}{
			"user_id":  userID,
			"org_id":   orgID,
			"name":     name,
			"email":    email,
			"metadata": metadata,
		})
	}
}

// Handler: Create data (protected)
func handleCreateData(manager *apikeys.APIKeyManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse request body
		var req struct {
			Data string `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]string{
				"error": "Invalid request body",
			})
			return
		}

		// Get user info for audit
		userID := manager.UserID(r)
		orgID := manager.OrgID(r)

		// Simulate creating data
		result := map[string]interface{}{
			"id":         "data_123",
			"data":       req.Data,
			"created_by": userID,
			"org_id":     orgID,
			"created_at": time.Now().Format(time.RFC3339),
		}

		respondJSON(w, http.StatusCreated, result)
	}
}

// respondJSON writes a JSON response
func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
