// Prometheus Integration Example
//
// This example demonstrates full Prometheus integration with go-apikeys.
// It includes:
// - Complete metric collection (auth, operations, cache)
// - Prometheus scrape endpoint
// - Multiple protected endpoints for testing
// - Simulated load generator
//
// Run with Docker: docker-compose up
// Or standalone: go run main.go
//
// Access:
// - API: http://localhost:8080
// - Metrics: http://localhost:8080/metrics
// - Prometheus UI: http://localhost:9090 (if using docker-compose)

package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
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

	// Setup repository
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
	metrics := apikeys.NewPrometheusMetrics("goapi keys", registry)

	// Create audit logger (100% sampling for demo)
	audit := apikeys.NewStructuredAuditLogger(
		logger.Named("audit"),
		1.0,  // 100% sampling
		true, // Log success events
	)

	// Create observability
	obs := apikeys.NewObservability(metrics, audit, nil)

	// Create service with caching enabled
	service, err := apikeys.NewAPIKeyService(
		repo,
		logger,
		"prom_",
		32,
		100,  // cache size
		300,  // cache TTL (5 min)
	)
	if err != nil {
		log.Fatal("Failed to create service:", err)
	}
	service.SetObservability(obs)

	// Configure manager
	config := &apikeys.Config{
		Repository:   repo,
		Logger:       logger,
		ApiKeyPrefix: "prom_",
		ApiKeyLength: 32,
		HeaderKey:    "X-API-Key",
		EnableCRUD:   true,
	}
	config.ApplyDefaults()

	manager, err := apikeys.New(config)
	if err != nil {
		log.Fatal("Failed to create manager:", err)
	}
	manager.SetObservability(obs)

	// Create test API keys for different organizations
	ctx := context.Background()
	testKeys := createTestKeys(ctx, service, logger)

	// Print test keys
	printTestKeys(testKeys)

	// Setup HTTP routes
	mux := http.NewServeMux()

	// Metrics endpoint (Prometheus scrapes this)
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))

	// Health endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Protected endpoints
	protectedMux := http.NewServeMux()

	// Fast endpoint (< 10ms)
	protectedMux.HandleFunc("/api/fast", func(w http.ResponseWriter, r *http.Request) {
		userID := manager.UserID(r)
		orgID := manager.OrgID(r)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"endpoint":"fast","user":"%s","org":"%s"}`, userID, orgID)
	})

	// Slow endpoint (100-200ms)
	protectedMux.HandleFunc("/api/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Duration(100+rand.Intn(100)) * time.Millisecond)
		userID := manager.UserID(r)
		orgID := manager.OrgID(r)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"endpoint":"slow","user":"%s","org":"%s"}`, userID, orgID)
	})

	// Error endpoint (50% fail rate)
	protectedMux.HandleFunc("/api/error", func(w http.ResponseWriter, r *http.Request) {
		if rand.Float32() < 0.5 {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"simulated error"}`))
			return
		}
		userID := manager.UserID(r)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"endpoint":"error","user":"%s","status":"ok"}`, userID)
	})

	// Apply authentication middleware
	mux.Handle("/api/", manager.StdlibMiddleware()(protectedMux))

	// Start server
	server := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start load generator (optional, controlled by env var)
	if os.Getenv("ENABLE_LOAD_GENERATOR") == "true" {
		go loadGenerator(testKeys, logger)
	}

	// Start server
	go func() {
		logger.Info("Server starting on :8080")
		logger.Info("Metrics: http://localhost:8080/metrics")
		logger.Info("Prometheus UI: http://localhost:9090 (if using docker-compose)")

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

// createTestKeys creates API keys for different test scenarios
func createTestKeys(ctx context.Context, service *apikeys.APIKeyService, logger *zap.Logger) []*apikeys.APIKeyInfo {
	orgs := []struct {
		userID string
		orgID  string
		name   string
	}{
		{"user-alpha", "org-alpha", "Alpha Test Key"},
		{"user-beta", "org-beta", "Beta Test Key"},
		{"user-gamma", "org-gamma", "Gamma Test Key"},
	}

	var keys []*apikeys.APIKeyInfo
	for _, org := range orgs {
		key, err := service.CreateAPIKey(ctx, &apikeys.APIKeyInfo{
			UserID: org.userID,
			OrgID:  org.orgID,
			Name:   org.name,
		})
		if err != nil {
			logger.Error("Failed to create test key", zap.Error(err))
			continue
		}
		keys = append(keys, key)
	}

	return keys
}

func printTestKeys(keys []*apikeys.APIKeyInfo) {
	fmt.Printf("\n╔═════════════════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║                         TEST API KEYS CREATED                           ║\n")
	fmt.Printf("╠═════════════════════════════════════════════════════════════════════════╣\n")
	for i, key := range keys {
		fmt.Printf("║ %d. %-20s %-46s ║\n", i+1, key.OrgID, key.APIKey)
	}
	fmt.Printf("╚═════════════════════════════════════════════════════════════════════════╝\n\n")
}

// loadGenerator simulates API traffic for demo purposes
func loadGenerator(keys []*apikeys.APIKeyInfo, logger *zap.Logger) {
	if len(keys) == 0 {
		return
	}

	endpoints := []string{"/api/fast", "/api/slow", "/api/error"}
	client := &http.Client{Timeout: 5 * time.Second}

	logger.Info("Load generator started (10 req/sec)")

	ticker := time.NewTicker(100 * time.Millisecond) // 10 requests per second
	defer ticker.Stop()

	for range ticker.C {
		// Pick random key and endpoint
		key := keys[rand.Intn(len(keys))]
		endpoint := endpoints[rand.Intn(len(endpoints))]

		go func(apiKey, endpoint string) {
			req, err := http.NewRequest("GET", "http://localhost:8080"+endpoint, nil)
			if err != nil {
				return
			}
			req.Header.Set("X-API-Key", apiKey)

			_, err = client.Do(req)
			if err != nil {
				// Silently ignore errors in load generator
				return
			}
		}(key.APIKey, endpoint)
	}
}
