// Custom Provider Example
//
// This example demonstrates implementing custom observability providers.
// Shows how to integrate with your own metrics backend (DataDog, StatsD, etc.)
// and custom audit log aggregation (Elasticsearch, Splunk, etc.).
//
// Run: go run main.go

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/itsatony/go-datarepository"
	apikeys "github.com/vaudience/go-apikeys/v2"
)

// CustomMetricsProvider sends metrics to your backend (e.g., DataDog, StatsD)
type CustomMetricsProvider struct {
	logger *zap.Logger
}

func NewCustomMetricsProvider(logger *zap.Logger) *CustomMetricsProvider {
	return &CustomMetricsProvider{logger: logger}
}

func (m *CustomMetricsProvider) RecordAuthAttempt(ctx context.Context, labels map[string]string) {
	// Example: Send to DataDog, StatsD, CloudWatch, etc.
	m.logger.Info("METRIC: auth_attempt",
		zap.String("org_id", labels["org_id"]),
		zap.String("endpoint", labels["endpoint"]),
	)
	// statsd.Increment("apikeys.auth.attempts", tags)
	// datadog.Incr("apikeys.auth.attempts", tags, 1)
}

func (m *CustomMetricsProvider) RecordAuthSuccess(ctx context.Context, labels map[string]string) {
	m.logger.Info("METRIC: auth_success",
		zap.String("org_id", labels["org_id"]),
		zap.String("key_type", labels["key_type"]),
	)
}

func (m *CustomMetricsProvider) RecordAuthError(ctx context.Context, labels map[string]string, errorType string) {
	m.logger.Warn("METRIC: auth_error",
		zap.String("org_id", labels["org_id"]),
		zap.String("reason", errorType),
	)
}

func (m *CustomMetricsProvider) RecordAuthDuration(ctx context.Context, labels map[string]string, duration time.Duration) {
	m.logger.Info("METRIC: auth_duration",
		zap.String("org_id", labels["org_id"]),
		zap.Duration("duration", duration),
	)
	// statsd.Timing("apikeys.auth.duration", duration, tags)
}

func (m *CustomMetricsProvider) RecordOperation(ctx context.Context, operation string, labels map[string]string, duration time.Duration) {
	m.logger.Info("METRIC: operation",
		zap.String("operation", operation),
		zap.String("org_id", labels["org_id"]),
		zap.Duration("duration", duration),
	)
}

func (m *CustomMetricsProvider) RecordOperationError(ctx context.Context, operation string, labels map[string]string, errorType string) {
	m.logger.Error("METRIC: operation_error",
		zap.String("operation", operation),
		zap.String("error", errorType),
	)
}

func (m *CustomMetricsProvider) RecordCacheHit(ctx context.Context) {
	m.logger.Debug("METRIC: cache_hit")
}

func (m *CustomMetricsProvider) RecordCacheMiss(ctx context.Context) {
	m.logger.Debug("METRIC: cache_miss")
}

func (m *CustomMetricsProvider) RecordCacheEviction(ctx context.Context) {
	m.logger.Debug("METRIC: cache_eviction")
}

func (m *CustomMetricsProvider) RecordActiveKeys(ctx context.Context, count int64) {
	m.logger.Info("METRIC: active_keys", zap.Int64("count", count))
	// statsd.Gauge("apikeys.active_keys", count, tags)
}

// CustomAuditProvider sends audit logs to your aggregator (e.g., Elasticsearch, Splunk)
type CustomAuditProvider struct {
	logger *zap.Logger
}

func NewCustomAuditProvider(logger *zap.Logger) *CustomAuditProvider {
	return &CustomAuditProvider{logger: logger}
}

func (a *CustomAuditProvider) LogAuthAttempt(event *apikeys.AuditEvent) {
	// Example: Send to Elasticsearch, Splunk, Sumo Logic, etc.
	a.logger.Info("AUDIT: auth_attempt",
		zap.String("event_id", event.EventID),
		zap.String("event_type", string(event.EventType)),
		zap.String("user_id", event.Actor.UserID),
		zap.String("org_id", event.Actor.OrgID),
		zap.String("outcome", string(event.Outcome)),
		zap.String("ip", event.Actor.IPAddress),
	)
	// elasticsearch.Index("audit-logs", event)
	// splunk.Send(event)
}

func (a *CustomAuditProvider) LogKeyCreated(event *apikeys.AuditEvent) {
	a.logger.Info("AUDIT: key_created",
		zap.String("event_id", event.EventID),
		zap.String("target_user", event.TargetUserID),
		zap.String("target_org", event.TargetOrgID),
	)
}

func (a *CustomAuditProvider) LogKeyUpdated(event *apikeys.AuditEvent) {
	a.logger.Info("AUDIT: key_updated",
		zap.String("event_id", event.EventID),
		zap.Any("before", event.BeforeState),
		zap.Any("after", event.AfterState),
	)
}

func (a *CustomAuditProvider) LogKeyDeleted(event *apikeys.AuditEvent) {
	a.logger.Warn("AUDIT: key_deleted",
		zap.String("event_id", event.EventID),
		zap.String("target_user", event.TargetUserID),
		zap.Any("before", event.BeforeState),
	)
}

func (a *CustomAuditProvider) LogKeyAccessed(event *apikeys.AuditEvent) {
	a.logger.Debug("AUDIT: key_accessed",
		zap.String("event_id", event.EventID),
		zap.String("user_id", event.Actor.UserID),
	)
}

func (a *CustomAuditProvider) LogSecurityEvent(event *apikeys.AuditEvent) {
	a.logger.Error("AUDIT: security_event",
		zap.String("event_id", event.EventID),
		zap.String("event_type", string(event.EventType)),
		zap.String("description", event.ErrorCode),
	)
}

func main() {
	// Setup logger
	logger, err := zap.NewDevelopment()
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

	// Create CUSTOM providers
	metrics := NewCustomMetricsProvider(logger.Named("metrics"))
	audit := NewCustomAuditProvider(logger.Named("audit"))

	// Create observability with custom providers
	obs := apikeys.NewObservability(metrics, audit, nil)

	// Create service
	service, err := apikeys.NewAPIKeyService(repo, logger, "custom_", 32, 0, 0)
	if err != nil {
		log.Fatal("Failed to create service:", err)
	}
	service.SetObservability(obs)

	// Configure manager
	config := &apikeys.Config{
		Repository:   repo,
		Logger:       logger,
		ApiKeyPrefix: "custom_",
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
		UserID: "custom-user",
		OrgID:  "custom-org",
		Name:   "Custom Provider Test Key",
	})
	if err != nil {
		log.Fatal("Failed to create test key:", err)
	}

	fmt.Printf("\n╔═══════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║              CUSTOM PROVIDERS ACTIVE                          ║\n")
	fmt.Printf("╠═══════════════════════════════════════════════════════════════╣\n")
	fmt.Printf("║ Metrics:  CustomMetricsProvider (logs to stdout)             ║\n")
	fmt.Printf("║ Audit:    CustomAuditProvider (logs to stdout)               ║\n")
	fmt.Printf("║                                                               ║\n")
	fmt.Printf("║ In production, replace with:                                 ║\n")
	fmt.Printf("║ - DataDog, StatsD, CloudWatch metrics                        ║\n")
	fmt.Printf("║ - Elasticsearch, Splunk audit logs                           ║\n")
	fmt.Printf("╠═══════════════════════════════════════════════════════════════╣\n")
	fmt.Printf("║ Test Key: %-51s ║\n", testKey.APIKey)
	fmt.Printf("╚═══════════════════════════════════════════════════════════════╝\n\n")

	// Setup HTTP routes
	mux := http.NewServeMux()

	protectedMux := http.NewServeMux()
	protectedMux.HandleFunc("/api/hello", func(w http.ResponseWriter, r *http.Request) {
		userID := manager.UserID(r)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"message":"Hello from custom providers!","user":"%s"}`, userID)
	})

	mux.Handle("/api/", manager.StdlibMiddleware()(protectedMux))

	logger.Info("Server starting on :8080 (custom providers)")
	logger.Info("Watch logs for METRIC and AUDIT events")
	logger.Info("Test: curl -H \"X-API-Key: " + testKey.APIKey + "\" http://localhost:8080/api/hello")

	server := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Fatal(server.ListenAndServe())
}
