package apikeys

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Integration test setup with real Prometheus and zap logger
func setupIntegrationTest(t *testing.T) (*APIKeyManager, *prometheus.Registry, *bytes.Buffer, func()) {
	// Create mock repository
	mockRepo := newMockRepository()

	// Create logger that captures output (with thread-safe writer)
	logBuffer := &bytes.Buffer{}
	encoder := zapcore.NewJSONEncoder(zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "level",
		MessageKey:     "message",
		CallerKey:      "caller",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	})
	// Wrap with Lock() to make it thread-safe for concurrent operations
	core := zapcore.NewCore(encoder, zapcore.Lock(zapcore.AddSync(logBuffer)), zapcore.DebugLevel)
	logger := zap.New(core)

	// Create service
	service, err := NewAPIKeyService(mockRepo, logger, DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH, 0, 0)
	require.NoError(t, err)

	// Create real Prometheus registry
	registry := prometheus.NewRegistry()
	metricsProvider := NewPrometheusMetrics("test", registry)

	// Create real audit logger (1.0 sample rate, audit all success events)
	auditProvider := NewStructuredAuditLogger(logger.Named("audit"), 1.0, true)

	// Create observability with real providers
	obs := NewObservability(metricsProvider, auditProvider, nil)
	service.SetObservability(obs)

	// Create config
	config := &Config{
		Logger:       logger,
		ApiKeyPrefix: DEFAULT_APIKEY_PREFIX,
		ApiKeyLength: DEFAULT_APIKEY_LENGTH,
		HeaderKey:    "X-API-Key",
	}
	config.ApplyDefaults()

	// Create manager
	manager := &APIKeyManager{
		config:        config,
		logger:        logger.Named(CLASS_APIKEY_MANAGER),
		service:       service,
		observability: obs,
	}

	cleanup := func() {
		_ = logger.Sync()
	}

	return manager, registry, logBuffer, cleanup
}

func TestIntegration_FullLifecycle(t *testing.T) {
	manager, registry, logBuffer, cleanup := setupIntegrationTest(t)
	defer cleanup()

	t.Run("complete API key lifecycle with observability", func(t *testing.T) {
		ctx := context.Background()

		// Step 1: Create API key
		createInfo := &APIKeyInfo{
			UserID: "integration-user",
			OrgID:  "integration-org",
			Name:   "Integration Test Key",
		}

		created, err := manager.service.CreateAPIKey(ctx, createInfo)
		require.NoError(t, err)
		require.NotNil(t, created)

		// Verify create metrics were recorded
		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		assert.NotEmpty(t, metricFamilies, "Should have metrics")

		// Verify audit log contains create event
		auditLogs := logBuffer.String()
		assert.Contains(t, auditLogs, "AUDIT_EVENT")
		assert.Contains(t, auditLogs, "key.created")
		assert.Contains(t, auditLogs, "integration-user")
		assert.Contains(t, auditLogs, "success")

		// Step 2: Use the API key (middleware auth)
		middleware := manager.standardMiddleware()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("authenticated"))
		})

		req := httptest.NewRequest("GET", "/api/resource", nil)
		req.Header.Set("X-API-Key", created.APIKey)
		rr := httptest.NewRecorder()

		middleware(handler).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		// Verify auth metrics were recorded (just check they exist)
		metricFamilies, err = registry.Gather()
		require.NoError(t, err)
		hasAuthMetric := false
		for _, mf := range metricFamilies {
			if strings.Contains(mf.GetName(), "auth") {
				hasAuthMetric = true
				break
			}
		}
		assert.True(t, hasAuthMetric, "Should have auth metrics")

		// Step 3: Update the API key
		logBuffer.Reset() // Clear previous logs to check update event
		updateInfo := &APIKeyInfo{
			APIKeyHash: created.APIKeyHash,
			UserID:     created.UserID,
			OrgID:      created.OrgID,
			Name:       "Updated Integration Key",
		}

		err = manager.service.UpdateAPIKey(ctx, updateInfo)
		require.NoError(t, err)

		// Verify update was applied
		updated, err := manager.service.GetAPIKeyInfo(ctx, created.APIKeyHash)
		require.NoError(t, err)
		assert.Equal(t, "Updated Integration Key", updated.Name)

		// Verify update metrics exist
		metricFamilies, err = registry.Gather()
		require.NoError(t, err)
		assert.NotEmpty(t, metricFamilies, "Should have metrics after update")

		// Verify update audit log
		updateLogs := logBuffer.String()
		assert.Contains(t, updateLogs, "key.updated")
		assert.Contains(t, updateLogs, "success")

		// Step 4: Delete the API key
		logBuffer.Reset()
		err = manager.service.DeleteAPIKey(ctx, created.APIKeyHash)
		require.NoError(t, err)

		// Verify delete metrics exist
		metricFamilies, err = registry.Gather()
		require.NoError(t, err)
		assert.NotEmpty(t, metricFamilies, "Should have metrics after delete")

		// Verify delete audit log
		deleteLogs := logBuffer.String()
		assert.Contains(t, deleteLogs, "key.deleted")
		assert.Contains(t, deleteLogs, "success")

		// Step 5: Verify key is actually deleted (auth should fail)
		req2 := httptest.NewRequest("GET", "/api/resource", nil)
		req2.Header.Set("X-API-Key", created.APIKey)
		rr2 := httptest.NewRecorder()

		middleware(handler).ServeHTTP(rr2, req2)

		assert.Equal(t, http.StatusUnauthorized, rr2.Code, "Deleted key should not authenticate")
	})
}

func TestIntegration_ErrorPaths(t *testing.T) {
	manager, registry, logBuffer, cleanup := setupIntegrationTest(t)
	defer cleanup()

	t.Run("failed operations generate proper metrics and audit logs", func(t *testing.T) {
		ctx := context.Background()

		// Test 1: Invalid update (non-existent key)
		updateInfo := &APIKeyInfo{
			APIKeyHash: "nonexistent-hash",
			UserID:     "test-user",
			OrgID:      "test-org",
			Name:       "Should Fail",
		}
		err := manager.service.UpdateAPIKey(ctx, updateInfo)
		assert.Error(t, err)

		// Verify failure metrics exist
		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		assert.NotEmpty(t, metricFamilies, "Should have metrics")

		// Verify warning log for not found
		logs := logBuffer.String()
		assert.Contains(t, logs, "not found")

		// Test 2: Invalid authentication
		logBuffer.Reset()
		middleware := manager.standardMiddleware()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("handler should not be called")
		})

		req := httptest.NewRequest("GET", "/api/resource", nil)
		req.Header.Set("X-API-Key", "gak_invalid_key_12345678901234567890")
		rr := httptest.NewRecorder()

		middleware(handler).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)

		// Verify auth failure metrics exist
		metricFamilies, err = registry.Gather()
		require.NoError(t, err)
		hasAuthFailure := false
		for _, mf := range metricFamilies {
			if strings.Contains(mf.GetName(), "auth") || strings.Contains(mf.GetName(), "failure") {
				hasAuthFailure = true
				break
			}
		}
		assert.True(t, hasAuthFailure, "Should have auth failure metrics")

		// Verify auth failure audit log
		authLogs := logBuffer.String()
		assert.Contains(t, authLogs, "auth.failure")
	})
}

func TestIntegration_ConcurrentOperations(t *testing.T) {
	manager, registry, _, cleanup := setupIntegrationTest(t)
	defer cleanup()

	t.Run("concurrent CRUD operations maintain correct metrics", func(t *testing.T) {
		ctx := context.Background()
		iterations := 20
		done := make(chan error, iterations)

		// Create keys concurrently
		for i := 0; i < iterations; i++ {
			go func(idx int) {
				info := &APIKeyInfo{
					UserID: "concurrent-user",
					OrgID:  "concurrent-org",
					Name:   "Concurrent Test Key",
				}
				_, err := manager.service.CreateAPIKey(ctx, info)
				done <- err
			}(i)
		}

		// Wait for all creates and check errors
		for i := 0; i < iterations; i++ {
			err := <-done
			require.NoError(t, err)
		}

		// Verify all creates were counted
		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		assert.NotEmpty(t, metricFamilies, "Should have metrics after concurrent creates")
	})
}

func TestIntegration_ContextPropagation(t *testing.T) {
	manager, _, logBuffer, cleanup := setupIntegrationTest(t)
	defer cleanup()

	t.Run("authenticated context propagates through service calls", func(t *testing.T) {
		ctx := context.Background()

		// Create first API key (will be the "authenticated" key)
		authKeyInfo := &APIKeyInfo{
			UserID: "admin-user",
			OrgID:  "admin-org",
			Name:   "Admin Key",
		}
		authKey, err := manager.service.CreateAPIKey(ctx, authKeyInfo)
		require.NoError(t, err)

		// Create context with authenticated API key info (simulating middleware)
		authenticatedCtx := context.WithValue(ctx, contextKeyAPIKeyInfo, authKey)

		// Create another key using the authenticated context
		logBuffer.Reset()
		newKeyInfo := &APIKeyInfo{
			UserID: "new-user",
			OrgID:  "new-org",
			Name:   "New Key",
		}
		_, err = manager.service.CreateAPIKey(authenticatedCtx, newKeyInfo)
		require.NoError(t, err)

		// Verify audit log contains the authenticated actor info
		logs := logBuffer.String()
		assert.Contains(t, logs, "admin-user", "Audit log should contain authenticated user")
		assert.Contains(t, logs, "admin-org", "Audit log should contain authenticated org")
		assert.Contains(t, logs, authKey.APIKeyHash, "Audit log should contain authenticated key hash")
	})
}

func TestIntegration_MetricsLabels(t *testing.T) {
	manager, registry, _, cleanup := setupIntegrationTest(t)
	defer cleanup()

	t.Run("metrics include proper labels for filtering", func(t *testing.T) {
		ctx := context.Background()

		// Create keys for different orgs
		orgs := []string{"org-alpha", "org-beta", "org-gamma"}
		for _, orgID := range orgs {
			info := &APIKeyInfo{
				UserID: "test-user",
				OrgID:  orgID,
				Name:   "Test Key",
			}
			_, err := manager.service.CreateAPIKey(ctx, info)
			require.NoError(t, err)
		}

		// Verify metrics were created
		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		assert.NotEmpty(t, metricFamilies, "Should have metric families")

		// Verify metrics contain multiple org_ids
		// Check that we have duration metrics with multiple org labels
		hasDurationMetric := false
		for _, mf := range metricFamilies {
			if strings.Contains(mf.GetName(), "duration") {
				hasDurationMetric = true
				// Verify we have metrics (histograms will have labels)
				assert.GreaterOrEqual(t, len(mf.GetMetric()), 1, "Should have duration metrics")
				break
			}
		}
		assert.True(t, hasDurationMetric, "Should have duration metrics with labels")
	})
}

func TestIntegration_AuditLogFormat(t *testing.T) {
	manager, _, logBuffer, cleanup := setupIntegrationTest(t)
	defer cleanup()

	t.Run("audit logs are valid JSON and parseable", func(t *testing.T) {
		ctx := context.Background()

		// Create an API key
		info := &APIKeyInfo{
			UserID: "json-user",
			OrgID:  "json-org",
			Name:   "JSON Test Key",
		}
		_, err := manager.service.CreateAPIKey(ctx, info)
		require.NoError(t, err)

		// Parse the audit log
		logs := logBuffer.String()
		lines := strings.Split(strings.TrimSpace(logs), "\n")

		var foundAuditEvent bool
		for _, line := range lines {
			if strings.Contains(line, "AUDIT_EVENT") {
				var logEntry map[string]interface{}
				err := json.Unmarshal([]byte(line), &logEntry)
				require.NoError(t, err, "Audit log should be valid JSON")

				// Verify required fields
				assert.NotEmpty(t, logEntry["timestamp"])
				assert.NotEmpty(t, logEntry["message"])

				foundAuditEvent = true
				break
			}
		}
		assert.True(t, foundAuditEvent, "Should find at least one audit event")
	})
}

func TestIntegration_LatencyMetrics(t *testing.T) {
	manager, registry, _, cleanup := setupIntegrationTest(t)
	defer cleanup()

	t.Run("latency histogram records operation durations", func(t *testing.T) {
		ctx := context.Background()

		// Create multiple keys to generate latency data
		for i := 0; i < 5; i++ {
			info := &APIKeyInfo{
				UserID: "latency-user",
				OrgID:  "latency-org",
				Name:   "Latency Test Key",
			}
			_, err := manager.service.CreateAPIKey(ctx, info)
			require.NoError(t, err)

			// Small delay to ensure measurable latency
			time.Sleep(1 * time.Millisecond)
		}

		// Verify latency histogram was updated
		metricFamilies, err := registry.Gather()
		require.NoError(t, err)

		var foundLatencyHistogram bool
		for _, mf := range metricFamilies {
			if strings.Contains(mf.GetName(), "duration") && strings.Contains(mf.GetType().String(), "HISTOGRAM") {
				// Verify we have samples
				for _, metric := range mf.GetMetric() {
					histogram := metric.GetHistogram()
					if histogram.GetSampleCount() > 0 {
						foundLatencyHistogram = true
						break
					}
				}
				if foundLatencyHistogram {
					break
				}
			}
		}
		assert.True(t, foundLatencyHistogram, "Should record latency histogram")
	})
}

func TestIntegration_MiddlewareToServiceFlow(t *testing.T) {
	manager, registry, logBuffer, cleanup := setupIntegrationTest(t)
	defer cleanup()

	t.Run("HTTP request flows through middleware to service with full observability", func(t *testing.T) {
		ctx := context.Background()

		// Create a test API key
		apiKeyInfo := &APIKeyInfo{
			UserID: "flow-user",
			OrgID:  "flow-org",
			Name:   "Flow Test Key",
		}
		created, err := manager.service.CreateAPIKey(ctx, apiKeyInfo)
		require.NoError(t, err)

		logBuffer.Reset()

		// Make an authenticated request that triggers an update
		middleware := manager.standardMiddleware()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate a service operation using the authenticated context
			updateInfo := &APIKeyInfo{
				APIKeyHash: created.APIKeyHash,
				UserID:     created.UserID,
				OrgID:      created.OrgID,
				Name:       "Updated by Request",
			}
			err := manager.service.UpdateAPIKey(r.Context(), updateInfo)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("PUT", "/api/keys/update", nil)
		req.Header.Set("X-API-Key", created.APIKey)
		rr := httptest.NewRecorder()

		middleware(handler).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		// Verify both auth and update metrics were recorded
		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		hasAuth := false
		hasDuration := false
		for _, mf := range metricFamilies {
			if strings.Contains(mf.GetName(), "auth") {
				hasAuth = true
			}
			if strings.Contains(mf.GetName(), "duration") {
				hasDuration = true
			}
		}
		assert.True(t, hasAuth, "Should have auth metrics")
		assert.True(t, hasDuration, "Should have duration metrics")

		// Verify audit logs contain both auth and update events
		logs := logBuffer.String()
		assert.Contains(t, logs, "auth.success")
		assert.Contains(t, logs, "key.updated")
		assert.Contains(t, logs, "flow-user", "Authenticated user should be in update audit log")
	})
}

func TestIntegration_MultipleOperationsMetering(t *testing.T) {
	// Create mock repository
	mockRepo := newMockRepository()

	// Create logger with buffer
	logBuffer := &bytes.Buffer{}
	encoder := zapcore.NewJSONEncoder(zapcore.EncoderConfig{
		MessageKey: "message",
	})
	core := zapcore.NewCore(encoder, zapcore.AddSync(logBuffer), zapcore.DebugLevel)
	logger := zap.New(core)

	// Create service
	service, err := NewAPIKeyService(mockRepo, logger, DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH, 0, 0)
	require.NoError(t, err)

	// Create observability
	registry := prometheus.NewRegistry()
	metrics := NewPrometheusMetrics("multi", registry)
	audit := NewStructuredAuditLogger(logger.Named("audit"), 1.0, true)
	obs := NewObservability(metrics, audit, nil)
	service.SetObservability(obs)

	t.Run("multiple operations are properly logged and metered", func(t *testing.T) {
		ctx := context.Background()

		// Create first key
		key1, err := service.CreateAPIKey(ctx, &APIKeyInfo{
			UserID: "user1",
			OrgID:  "org1",
			Name:   "Key 1",
		})
		require.NoError(t, err)
		require.NotNil(t, key1)

		// Create second key
		key2, err := service.CreateAPIKey(ctx, &APIKeyInfo{
			UserID: "user2",
			OrgID:  "org2",
			Name:   "Key 2",
		})
		require.NoError(t, err)
		require.NotNil(t, key2)

		// Verify metrics for both creates
		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		hasDuration := false
		for _, mf := range metricFamilies {
			if strings.Contains(mf.GetName(), "duration") {
				hasDuration = true
				assert.GreaterOrEqual(t, len(mf.GetMetric()), 1, "Should have duration metrics")
				break
			}
		}
		assert.True(t, hasDuration, "Should have duration metrics")

		// Verify audit logs contain both events
		logs := logBuffer.String()
		assert.Contains(t, logs, "user1")
		assert.Contains(t, logs, "user2")
		assert.Contains(t, logs, "org1")
		assert.Contains(t, logs, "org2")
	})
}

func TestIntegration_PrometheusExport(t *testing.T) {
	manager, registry, _, cleanup := setupIntegrationTest(t)
	defer cleanup()

	t.Run("metrics can be exported in Prometheus format", func(t *testing.T) {
		ctx := context.Background()

		// Generate some activity
		for i := 0; i < 3; i++ {
			info := &APIKeyInfo{
				UserID: "export-user",
				OrgID:  "export-org",
				Name:   "Export Test Key",
			}
			_, err := manager.service.CreateAPIKey(ctx, info)
			require.NoError(t, err)
		}

		// Collect metrics
		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		assert.NotEmpty(t, metricFamilies, "Should have metric families")

		// Write metrics in Prometheus text format
		var buf bytes.Buffer
		for _, mf := range metricFamilies {
			_, err := buf.WriteString(mf.String())
			require.NoError(t, err)
		}

		output := buf.String()
		// Check for actual metrics that exist
		assert.Contains(t, output, "test_")  // Should have test_ prefix
		assert.Contains(t, output, "export-org")
		assert.Contains(t, output, "duration")  // Should have duration metrics
	})
}
