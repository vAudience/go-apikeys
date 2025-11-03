// SOC 2 Type II Compliance Example
//
// This example demonstrates compliance-focused audit logging for SOC 2 Type II.
// Key features:
// - 100% audit sampling (required for compliance)
// - Complete audit trail of all operations
// - Actor tracking (who, what, when, where)
// - Before/after state capture
//
// Run: go run main.go

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/itsatony/go-datarepository"
	apikeys "github.com/vaudience/go-apikeys/v2"
)

func main() {
	// Setup production logger with JSON output (required for compliance)
	config := zap.NewProductionConfig()
	config.EncoderConfig.TimeKey = "timestamp"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	logger, err := config.Build()
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

	// Create Prometheus metrics
	registry := prometheus.NewRegistry()
	metrics := apikeys.NewPrometheusMetrics("compliance", registry)

	// Create audit logger with SOC 2 compliance mode
	audit := apikeys.NewStructuredAuditLogger(
		logger.Named("audit"),
		1.0,  // 100% sampling (REQUIRED for SOC 2)
		true, // Log all success events (REQUIRED)
	)

	// Set compliance mode (enforces SOC 2 requirements)
	audit.SetComplianceMode(apikeys.ComplianceSOC2)

	// Create observability
	obs := apikeys.NewObservability(metrics, audit, nil)

	// Create service
	service, err := apikeys.NewAPIKeyService(repo, logger, "soc2_", 32, 0, 0)
	if err != nil {
		log.Fatal("Failed to create service:", err)
	}
	service.SetObservability(obs)

	// Configure manager
	config := &apikeys.Config{
		Repository:   repo,
		Logger:       logger,
		ApiKeyPrefix: "soc2_",
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

	// Create test API key
	ctx := context.Background()
	testKey, err := service.CreateAPIKey(ctx, &apikeys.APIKeyInfo{
		UserID: "compliance-user",
		OrgID:  "compliance-org",
		Name:   "Compliance Test Key",
		Email:  "compliance@example.com",
	})
	if err != nil {
		log.Fatal("Failed to create test key:", err)
	}

	fmt.Printf("\n╔═════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║           SOC 2 COMPLIANCE MODE ACTIVE                      ║\n")
	fmt.Printf("╠═════════════════════════════════════════════════════════════╣\n")
	fmt.Printf("║ - 100%% audit sampling                                      ║\n")
	fmt.Printf("║ - All operations logged                                     ║\n")
	fmt.Printf("║ - Complete actor tracking                                   ║\n")
	fmt.Printf("║ - Before/after state capture                                ║\n")
	fmt.Printf("╠═════════════════════════════════════════════════════════════╣\n")
	fmt.Printf("║ Test Key: %-49s ║\n", testKey.APIKey)
	fmt.Printf("╚═════════════════════════════════════════════════════════════╝\n\n")

	// Setup HTTP routes
	mux := http.NewServeMux()

	// Protected endpoint
	protectedMux := http.NewServeMux()
	protectedMux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		userID := manager.UserID(r)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"message":"Data access logged","user":"%s"}`, userID)
	})

	mux.Handle("/api/", manager.StdlibMiddleware()(protectedMux))

	// Start server
	logger.Info("Server starting on :8080 (SOC 2 compliance mode)")
	logger.Info("All operations are being audited with 100% sampling")
	logger.Info("Test: curl -H \"X-API-Key: " + testKey.APIKey + "\" http://localhost:8080/api/data")

	server := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Fatal(server.ListenAndServe())
}
