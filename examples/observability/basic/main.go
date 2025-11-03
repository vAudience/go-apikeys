// Basic Observability Example
//
// This example demonstrates minimal observability setup with go-apikeys.
// It shows how to enable Prometheus metrics and basic audit logging.
//
// Run: go run main.go
// Test: curl -H "X-API-Key: <your-key>" http://localhost:8080/api/hello
// Metrics: curl http://localhost:8080/metrics

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/itsatony/go-datarepository"
	apikeys "github.com/vaudience/go-apikeys/v2"
)

func main() {
	// Setup logger
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatal("Failed to create logger:", err)
	}
	defer logger.Sync()

	// Setup repository (in-memory for this example)
	repo, err := datarepository.CreateDataRepository("memory",
		datarepository.NewMemoryConfig(
			"apikeys",
			":",
			func(level, msg string) { logger.Info(msg) },
		))
	if err != nil {
		log.Fatal("Failed to create repository:", err)
	}

	// Create Prometheus metrics provider
	registry := prometheus.NewRegistry()
	metrics := apikeys.NewPrometheusMetrics("example", registry)

	// Create audit logger (10% sample rate, log success events)
	audit := apikeys.NewStructuredAuditLogger(
		logger.Named("audit"),
		0.1,  // Sample 10% of successful requests
		true, // Log success events
	)

	// Create observability (no tracing for this example)
	obs := apikeys.NewObservability(metrics, audit, nil)

	// Create service
	service, err := apikeys.NewAPIKeyService(
		repo,
		logger,
		"ex_",  // prefix
		32,     // length
		100,    // cache size
		300,    // cache TTL (5 min)
	)
	if err != nil {
		log.Fatal("Failed to create service:", err)
	}

	// Attach observability to service
	service.SetObservability(obs)

	// Configure manager
	config := &apikeys.Config{
		Repository:   repo,
		Logger:       logger,
		ApiKeyPrefix: "ex_",
		ApiKeyLength: 32,
		HeaderKey:    "X-API-Key",
		EnableCRUD:   true,
	}
	config.ApplyDefaults()

	manager, err := apikeys.New(config)
	if err != nil {
		log.Fatal("Failed to create manager:", err)
	}

	// Attach observability to manager
	manager.SetObservability(obs)

	// Create bootstrap API key for testing
	ctx := context.Background()
	testKey, err := service.CreateAPIKey(ctx, &apikeys.APIKeyInfo{
		UserID: "test-user",
		OrgID:  "test-org",
		Name:   "Test Key",
		Email:  "test@example.com",
	})
	if err != nil {
		log.Fatal("Failed to create test key:", err)
	}

	// Print the test key (for demo purposes only!)
	fmt.Printf("\n╔═══════════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║                     TEST API KEY CREATED                          ║\n")
	fmt.Printf("╠═══════════════════════════════════════════════════════════════════╣\n")
	fmt.Printf("║ API Key: %-57s ║\n", testKey.APIKey)
	fmt.Printf("║ Hint:    %-57s ║\n", testKey.Hint)
	fmt.Printf("╚═══════════════════════════════════════════════════════════════════╝\n\n")

	// Setup HTTP routes
	mux := http.NewServeMux()

	// Metrics endpoint (no authentication required)
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))

	// Health endpoint (no authentication required)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Protected endpoint
	protectedMux := http.NewServeMux()
	protectedMux.HandleFunc("/api/hello", func(w http.ResponseWriter, r *http.Request) {
		userID := manager.UserID(r)
		orgID := manager.OrgID(r)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"message":"Hello, %s!","org_id":"%s"}`, userID, orgID)
	})

	// Apply authentication middleware only to /api/* routes
	mux.Handle("/api/", manager.StdlibMiddleware()(protectedMux))

	// Start server
	server := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		logger.Info("Server starting on :8080")
		logger.Info("Metrics available at http://localhost:8080/metrics")
		logger.Info("Test endpoint: curl -H \"X-API-Key: " + testKey.APIKey + "\" http://localhost:8080/api/hello")

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Server failed", zap.Error(err))
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown", zap.Error(err))
	}

	logger.Info("Server exited")
}
