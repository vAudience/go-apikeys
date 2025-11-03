package apikeys

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPrometheusMetrics(t *testing.T) {
	t.Run("creates metrics with default namespace", func(t *testing.T) {
		metrics := NewPrometheusMetrics("", nil)

		require.NotNil(t, metrics)
		assert.Equal(t, "apikeys", metrics.namespace)
		assert.NotNil(t, metrics.authAttempts)
		assert.NotNil(t, metrics.authLatency)
		assert.NotNil(t, metrics.authErrors)
		assert.NotNil(t, metrics.operationLatency)
		assert.NotNil(t, metrics.cacheHits)
		assert.NotNil(t, metrics.cacheMisses)
		assert.NotNil(t, metrics.activeKeys)
	})

	t.Run("creates metrics with custom namespace", func(t *testing.T) {
		metrics := NewPrometheusMetrics("myapp", nil)

		require.NotNil(t, metrics)
		assert.Equal(t, "myapp", metrics.namespace)
	})

	t.Run("creates metrics with custom registry", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := NewPrometheusMetrics("test", registry)

		require.NotNil(t, metrics)
		assert.Equal(t, registry, metrics.registry)
	})
}

func TestPrometheusMetrics_RecordAuthAttempt(t *testing.T) {
	ctx := context.Background()

	t.Run("records successful auth attempt", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := NewPrometheusMetrics("test", registry)

		metrics.RecordAuthAttempt(ctx, true, 10*time.Millisecond, map[string]string{
			"org_id":   "test-org",
			"endpoint": "/api/users",
		})

		// Verify metric was recorded
		metricFamilies, err := registry.Gather()
		require.NoError(t, err)

		// Find auth_attempts_total metric
		found := false
		for _, mf := range metricFamilies {
			if *mf.Name == "test_auth_attempts_total" {
				found = true
				assert.Equal(t, 1, len(mf.Metric))
				assert.Equal(t, float64(1), *mf.Metric[0].Counter.Value)
			}
		}
		assert.True(t, found, "auth_attempts_total metric not found")
	})

	t.Run("records failed auth attempt", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := NewPrometheusMetrics("test", registry)

		metrics.RecordAuthAttempt(ctx, false, 5*time.Millisecond, map[string]string{
			"org_id": "test-org",
		})

		// Verify metric was recorded with outcome=failure
		metricFamilies, err := registry.Gather()
		require.NoError(t, err)

		found := false
		for _, mf := range metricFamilies {
			if *mf.Name == "test_auth_attempts_total" {
				found = true
			}
		}
		assert.True(t, found)
	})

	t.Run("records auth latency histogram", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := NewPrometheusMetrics("test", registry)

		// Record multiple attempts with different latencies
		metrics.RecordAuthAttempt(ctx, true, 1*time.Millisecond, nil)
		metrics.RecordAuthAttempt(ctx, true, 10*time.Millisecond, nil)
		metrics.RecordAuthAttempt(ctx, true, 100*time.Millisecond, nil)

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)

		// Find auth_duration_seconds histogram
		found := false
		for _, mf := range metricFamilies {
			if *mf.Name == "test_auth_duration_seconds" {
				found = true
				// Histogram should have count and sum
				assert.Greater(t, *mf.Metric[0].Histogram.SampleCount, uint64(0))
			}
		}
		assert.True(t, found, "auth_duration_seconds histogram not found")
	})

	t.Run("handles nil labels gracefully", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := NewPrometheusMetrics("test", registry)

		assert.NotPanics(t, func() {
			metrics.RecordAuthAttempt(ctx, true, time.Millisecond, nil)
		})
	})

	t.Run("handles empty labels gracefully", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := NewPrometheusMetrics("test", registry)

		assert.NotPanics(t, func() {
			metrics.RecordAuthAttempt(ctx, true, time.Millisecond, map[string]string{})
		})
	})
}

func TestPrometheusMetrics_RecordAuthError(t *testing.T) {
	ctx := context.Background()

	t.Run("records auth error by type", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := NewPrometheusMetrics("test", registry)

		metrics.RecordAuthError(ctx, "key_not_found", map[string]string{
			"endpoint": "/api/users",
		})

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)

		// Find auth_errors_total metric
		found := false
		for _, mf := range metricFamilies {
			if *mf.Name == "test_auth_errors_total" {
				found = true
				assert.Equal(t, float64(1), *mf.Metric[0].Counter.Value)
			}
		}
		assert.True(t, found, "auth_errors_total metric not found")
	})

	t.Run("records multiple error types separately", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := NewPrometheusMetrics("test", registry)

		metrics.RecordAuthError(ctx, "key_not_found", map[string]string{"endpoint": "/api"})
		metrics.RecordAuthError(ctx, "key_invalid", map[string]string{"endpoint": "/api"})
		metrics.RecordAuthError(ctx, "key_not_found", map[string]string{"endpoint": "/api"})

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)

		// Should have metrics for both error types
		for _, mf := range metricFamilies {
			if *mf.Name == "test_auth_errors_total" {
				// Should have 2 different label combinations (key_not_found and key_invalid)
				assert.GreaterOrEqual(t, len(mf.Metric), 2)
			}
		}
	})
}

func TestPrometheusMetrics_RecordOperation(t *testing.T) {
	ctx := context.Background()

	t.Run("records operation latency", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := NewPrometheusMetrics("test", registry)

		metrics.RecordOperation(ctx, "create_key", 20*time.Millisecond, map[string]string{
			"org_id": "test-org",
		})

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)

		found := false
		for _, mf := range metricFamilies {
			if *mf.Name == "test_operation_duration_seconds" {
				found = true
				assert.Greater(t, *mf.Metric[0].Histogram.SampleCount, uint64(0))
			}
		}
		assert.True(t, found, "operation_duration_seconds histogram not found")
	})

	t.Run("records different operations separately", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := NewPrometheusMetrics("test", registry)

		metrics.RecordOperation(ctx, "create_key", 10*time.Millisecond, map[string]string{"org_id": "org1"})
		metrics.RecordOperation(ctx, "delete_key", 5*time.Millisecond, map[string]string{"org_id": "org1"})

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)

		for _, mf := range metricFamilies {
			if *mf.Name == "test_operation_duration_seconds" {
				// Should have metrics for different operations
				assert.GreaterOrEqual(t, len(mf.Metric), 2)
			}
		}
	})
}

func TestPrometheusMetrics_RecordOperationError(t *testing.T) {
	ctx := context.Background()

	t.Run("records operation error", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := NewPrometheusMetrics("test", registry)

		metrics.RecordOperationError(ctx, "create_key", "validation_error")

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)

		found := false
		for _, mf := range metricFamilies {
			if *mf.Name == "test_operation_errors_total" {
				found = true
				assert.Equal(t, float64(1), *mf.Metric[0].Counter.Value)
			}
		}
		assert.True(t, found, "operation_errors_total metric not found")
	})
}

func TestPrometheusMetrics_CacheMetrics(t *testing.T) {
	ctx := context.Background()

	t.Run("records cache hits", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := NewPrometheusMetrics("test", registry)

		metrics.RecordCacheHit(ctx, "key1")
		metrics.RecordCacheHit(ctx, "key2")

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)

		found := false
		for _, mf := range metricFamilies {
			if *mf.Name == "test_cache_hits_total" {
				found = true
				assert.Equal(t, float64(2), *mf.Metric[0].Counter.Value)
			}
		}
		assert.True(t, found, "cache_hits_total metric not found")
	})

	t.Run("records cache misses", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := NewPrometheusMetrics("test", registry)

		metrics.RecordCacheMiss(ctx, "key1")
		metrics.RecordCacheMiss(ctx, "key2")
		metrics.RecordCacheMiss(ctx, "key3")

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)

		found := false
		for _, mf := range metricFamilies {
			if *mf.Name == "test_cache_misses_total" {
				found = true
				assert.Equal(t, float64(3), *mf.Metric[0].Counter.Value)
			}
		}
		assert.True(t, found, "cache_misses_total metric not found")
	})

	t.Run("records cache evictions by reason", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := NewPrometheusMetrics("test", registry)

		metrics.RecordCacheEviction(ctx, "size")
		metrics.RecordCacheEviction(ctx, "ttl")
		metrics.RecordCacheEviction(ctx, "size")

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)

		found := false
		for _, mf := range metricFamilies {
			if *mf.Name == "test_cache_evictions_total" {
				found = true
				// Should have metrics for both reasons
				assert.GreaterOrEqual(t, len(mf.Metric), 2)
			}
		}
		assert.True(t, found, "cache_evictions_total metric not found")
	})
}

func TestPrometheusMetrics_RecordActiveKeys(t *testing.T) {
	ctx := context.Background()

	t.Run("records active keys gauge", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := NewPrometheusMetrics("test", registry)

		metrics.RecordActiveKeys(ctx, 100)

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)

		found := false
		for _, mf := range metricFamilies {
			if *mf.Name == "test_active_keys" {
				found = true
				assert.Equal(t, float64(100), *mf.Metric[0].Gauge.Value)
			}
		}
		assert.True(t, found, "active_keys gauge not found")
	})

	t.Run("updates gauge value", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := NewPrometheusMetrics("test", registry)

		metrics.RecordActiveKeys(ctx, 100)
		metrics.RecordActiveKeys(ctx, 150)

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)

		for _, mf := range metricFamilies {
			if *mf.Name == "test_active_keys" {
				// Gauge should show latest value
				assert.Equal(t, float64(150), *mf.Metric[0].Gauge.Value)
			}
		}
	})
}

func TestPrometheusMetrics_Handler(t *testing.T) {
	t.Run("handler returns metrics endpoint", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := NewPrometheusMetrics("test", registry)

		// Record some metrics
		metrics.RecordAuthAttempt(context.Background(), true, time.Millisecond, nil)
		metrics.RecordCacheHit(context.Background(), "key1")

		// Create test HTTP server
		handler := metrics.Handler()
		req := httptest.NewRequest("GET", "/metrics", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		body, err := io.ReadAll(w.Body)
		require.NoError(t, err)

		bodyStr := string(body)
		assert.Contains(t, bodyStr, "test_auth_attempts_total")
		assert.Contains(t, bodyStr, "test_cache_hits_total")
	})

	t.Run("handler supports OpenMetrics format", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := NewPrometheusMetrics("test", registry)

		handler := metrics.Handler()
		req := httptest.NewRequest("GET", "/metrics", nil)
		req.Header.Set("Accept", "application/openmetrics-text")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "application/openmetrics-text")
	})
}

func TestPrometheusMetrics_Registry(t *testing.T) {
	t.Run("returns registry", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := NewPrometheusMetrics("test", registry)

		assert.Equal(t, registry, metrics.Registry())
	})
}

func TestPrometheusMetrics_ConcurrentAccess(t *testing.T) {
	t.Run("concurrent metric recording is thread-safe", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := NewPrometheusMetrics("test", registry)
		ctx := context.Background()

		done := make(chan bool)
		iterations := 100

		for i := 0; i < iterations; i++ {
			go func() {
				metrics.RecordAuthAttempt(ctx, true, time.Millisecond, nil)
				metrics.RecordOperation(ctx, "test", time.Millisecond, nil)
				metrics.RecordCacheHit(ctx, "key")
				metrics.RecordActiveKeys(ctx, 10)
				done <- true
			}()
		}

		for i := 0; i < iterations; i++ {
			<-done
		}

		// Verify metrics were recorded
		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		assert.Greater(t, len(metricFamilies), 0)
	})
}

func TestPrometheusMetrics_LabelHandling(t *testing.T) {
	ctx := context.Background()

	t.Run("uses default values for missing labels", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := NewPrometheusMetrics("test", registry)

		// Record with missing org_id label
		metrics.RecordAuthAttempt(ctx, true, time.Millisecond, map[string]string{})

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)

		// Should still record metric with default label value
		found := false
		for _, mf := range metricFamilies {
			if *mf.Name == "test_auth_attempts_total" {
				found = true
				// Should have metric with default org_id="unknown"
				assert.Greater(t, len(mf.Metric), 0)
			}
		}
		assert.True(t, found)
	})

	t.Run("handles special characters in labels", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := NewPrometheusMetrics("test", registry)

		assert.NotPanics(t, func() {
			metrics.RecordAuthAttempt(ctx, true, time.Millisecond, map[string]string{
				"org_id": "test-org-123",
			})
		})
	})
}

func TestPrometheusMetrics_MetricNaming(t *testing.T) {
	t.Run("metrics follow Prometheus naming conventions", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := NewPrometheusMetrics("myapp", registry)

		metrics.RecordAuthAttempt(context.Background(), true, time.Millisecond, nil)
		metrics.RecordOperation(context.Background(), "test", time.Millisecond, nil)
		metrics.RecordCacheHit(context.Background(), "key")
		metrics.RecordActiveKeys(context.Background(), 10)

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)

		// Check metric names follow conventions
		expectedMetrics := []string{
			"myapp_auth_attempts_total",      // counter
			"myapp_auth_duration_seconds",    // histogram
			"myapp_operation_duration_seconds", // histogram
			"myapp_cache_hits_total",         // counter
			"myapp_active_keys",              // gauge
		}

		foundMetrics := make(map[string]bool)
		for _, mf := range metricFamilies {
			foundMetrics[*mf.Name] = true
		}

		for _, expectedMetric := range expectedMetrics {
			assert.True(t, foundMetrics[expectedMetric],
				"expected metric %s not found", expectedMetric)
		}
	})
}

func BenchmarkPrometheusMetrics(b *testing.B) {
	registry := prometheus.NewRegistry()
	metrics := NewPrometheusMetrics("test", registry)
	ctx := context.Background()
	labels := map[string]string{"org_id": "test"}

	b.Run("RecordAuthAttempt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			metrics.RecordAuthAttempt(ctx, true, time.Millisecond, labels)
		}
	})

	b.Run("RecordOperation", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			metrics.RecordOperation(ctx, "create_key", time.Millisecond, labels)
		}
	})

	b.Run("RecordCacheHit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			metrics.RecordCacheHit(ctx, "key")
		}
	})

	b.Run("RecordActiveKeys", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			metrics.RecordActiveKeys(ctx, 100)
		}
	})
}
