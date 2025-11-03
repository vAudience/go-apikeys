# Prometheus Integration Example

Complete production-like setup with Prometheus metrics, Grafana dashboards, and simulated load.

## Features

- ✅ Full Prometheus integration with scraping
- ✅ Grafana dashboards (pre-configured datasource)
- ✅ Load generator (10 req/sec)
- ✅ Multiple test endpoints (fast, slow, error)
- ✅ Multiple organizations for testing
- ✅ Docker Compose orchestration
- ✅ 100% audit sampling

## Quick Start with Docker

```bash
# Start all services (app + Prometheus + Grafana)
docker-compose up

# Access the services:
# - App API: http://localhost:8080
# - Prometheus: http://localhost:9090
# - Grafana: http://localhost:3000 (admin/admin)
```

## Run Standalone

```bash
# Run without Docker
go run main.go

# Enable load generator
ENABLE_LOAD_GENERATOR=true go run main.go
```

## Services

### Application (Port 8080)

API endpoints:
- `GET /api/fast` - Fast endpoint (<10ms)
- `GET /api/slow` - Slow endpoint (100-200ms)
- `GET /api/error` - Random errors (50% fail rate)
- `GET /metrics` - Prometheus metrics endpoint
- `GET /health` - Health check

### Prometheus (Port 9090)

Access Prometheus UI at http://localhost:9090

**Try these queries:**

```promql
# Authentication failure rate (per second)
rate(goapikeys_auth_failures_total[5m])

# P95 authentication latency by organization
histogram_quantile(0.95,
  sum(rate(goapikeys_auth_duration_seconds_bucket[5m])) by (le, org_id)
)

# Total authentication attempts by org
sum(rate(goapikeys_auth_attempts_total[5m])) by (org_id)

# Cache hit rate
rate(goapikeys_cache_hits_total[5m]) /
  (rate(goapikeys_cache_hits_total[5m]) + rate(goapikeys_cache_misses_total[5m]))

# Active API keys
goapikeys_active_keys

# Operation duration by operation type
histogram_quantile(0.99,
  sum(rate(goapikeys_operation_duration_seconds_bucket[5m])) by (le, operation)
)
```

### Grafana (Port 3000)

Access Grafana at http://localhost:3000
- Username: `admin`
- Password: `admin`

Datasource is pre-configured to connect to Prometheus.

**Create dashboards for:**
1. **Authentication Overview**
   - Auth attempts/sec
   - Success rate
   - Failure rate by reason
   - P95/P99 latency

2. **Per-Organization Metrics**
   - Requests by org_id
   - Latency by org_id
   - Error rate by org_id

3. **Cache Performance**
   - Hit rate %
   - Hits vs Misses
   - Evictions

4. **System Health**
   - Active API keys gauge
   - Operation latency histogram

## Testing the API

```bash
# The app prints test API keys on startup, use them:

# Fast endpoint
curl -H "X-API-Key: prom_xxx..." http://localhost:8080/api/fast

# Slow endpoint
curl -H "X-API-Key: prom_xxx..." http://localhost:8080/api/slow

# Error endpoint (50% fail rate)
curl -H "X-API-Key: prom_xxx..." http://localhost:8080/api/error

# Try invalid key (generates auth failure metrics)
curl -H "X-API-Key: invalid_key" http://localhost:8080/api/fast

# No key (generates missing key metrics)
curl http://localhost:8080/api/fast
```

## Load Generator

When `ENABLE_LOAD_GENERATOR=true`, the app generates:
- 10 requests per second
- Random distribution across 3 orgs
- Random distribution across 3 endpoints
- Mix of fast, slow, and error endpoints

This creates realistic metric patterns for dashboard testing.

## Metrics Available

All metrics have namespace prefix: `goapikeys_`

**Authentication:**
- `goapikeys_auth_attempts_total{endpoint, org_id}`
- `goapikeys_auth_successes_total{endpoint, org_id, key_type}`
- `goapikeys_auth_failures_total{endpoint, org_id, reason}`
- `goapikeys_auth_duration_seconds{endpoint, org_id}` (histogram)

**Operations:**
- `goapikeys_operation_duration_seconds{operation, org_id}` (histogram)
- `goapikeys_active_keys` (gauge)

**Cache:**
- `goapikeys_cache_hits_total`
- `goapikeys_cache_misses_total`
- `goapikeys_cache_evictions_total`

## Alerting Rules

Create `alerts.yml` (referenced in `prometheus.yml`):

```yaml
groups:
  - name: go-apikeys
    interval: 30s
    rules:
      # High authentication failure rate
      - alert: HighAuthFailureRate
        expr: rate(goapikeys_auth_failures_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High authentication failure rate"
          description: "{{ $value }} auth failures/sec (threshold: 10/sec)"

      # High P95 latency
      - alert: HighAuthLatency
        expr: |
          histogram_quantile(0.95,
            sum(rate(goapikeys_auth_duration_seconds_bucket[5m])) by (le)
          ) > 0.5
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Authentication latency P95 > 500ms"
          description: "P95 latency: {{ $value }}s"

      # Low cache hit rate
      - alert: LowCacheHitRate
        expr: |
          rate(goapikeys_cache_hits_total[5m]) /
          (rate(goapikeys_cache_hits_total[5m]) + rate(goapikeys_cache_misses_total[5m]))
          < 0.8
        for: 15m
        labels:
          severity: info
        annotations:
          summary: "Cache hit rate < 80%"
          description: "Hit rate: {{ $value | humanizePercentage }}"
```

## Docker Commands

```bash
# Start services
docker-compose up -d

# View logs
docker-compose logs -f app

# Stop services
docker-compose down

# Stop and remove volumes
docker-compose down -v

# Rebuild after code changes
docker-compose up --build
```

## Production Considerations

1. **Persistent Storage**: Prometheus and Grafana data is stored in Docker volumes
2. **Retention**: Prometheus configured for 7-day retention
3. **Scrape Interval**: 5 seconds (adjust based on traffic)
4. **Grafana Security**: Change default admin password!
5. **Resource Limits**: Add CPU/memory limits in docker-compose.yml
6. **TLS**: Enable HTTPS for production deployments
7. **Authentication**: Secure /metrics endpoint if publicly accessible

## Troubleshooting

**Prometheus not scraping:**
- Check `docker-compose logs prometheus`
- Verify app is running: `curl http://localhost:8080/metrics`
- Check Prometheus targets: http://localhost:9090/targets

**Grafana can't connect to Prometheus:**
- Verify datasource config: `grafana-datasources.yml`
- Check Grafana logs: `docker-compose logs grafana`
- Test connectivity: `docker-compose exec grafana ping prometheus`

**No metrics showing:**
- Ensure load generator is enabled: `ENABLE_LOAD_GENERATOR=true`
- Make manual API requests to generate metrics
- Check Prometheus query: `goapikeys_auth_attempts_total`

## Next Steps

- See `../compliance-soc2/` for compliance-focused logging
- See `../custom-provider/` for custom metrics backends
- See main README.md for alerting examples
