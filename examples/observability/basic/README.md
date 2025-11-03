# Basic Observability Example

Minimal observability setup showing Prometheus metrics and audit logging with go-apikeys.

## Features

- ✅ Prometheus metrics (auth attempts, successes, failures, latency)
- ✅ Structured JSON audit logging (10% sampling)
- ✅ In-memory storage (no external dependencies)
- ✅ Bootstrap API key for testing
- ✅ Graceful shutdown

## Quick Start

```bash
# Run the example
go run main.go

# The server will print a test API key like:
# API Key: ex_abc123...xyz789
```

## Testing

```bash
# Test authenticated endpoint
curl -H "X-API-Key: ex_your_key_here" \
  http://localhost:8080/api/hello

# Check metrics
curl http://localhost:8080/metrics

# Health check (no auth required)
curl http://localhost:8080/health
```

## Metrics Available

Visit `http://localhost:8080/metrics` to see:

- `example_auth_attempts_total` - Total authentication attempts
- `example_auth_successes_total` - Successful authentications
- `example_auth_failures_total` - Failed authentications
- `example_auth_duration_seconds` - Auth latency histogram
- `example_operation_duration_seconds` - Operation latency histogram
- `example_active_keys` - Current number of active API keys
- `example_cache_hits_total` - Cache hit count
- `example_cache_misses_total` - Cache miss count

## Audit Logs

Audit events are logged to stdout in JSON format. Look for logs with `"message":"AUDIT_EVENT"`.

Example audit event:
```json
{
  "level": "info",
  "timestamp": "2025-01-15T10:30:00Z",
  "message": "AUDIT_EVENT",
  "event_type": "auth.success",
  "event": {
    "event_id": "uuid",
    "event_type": "auth.success",
    "actor": {
      "user_id": "test-user",
      "org_id": "test-org"
    },
    "outcome": "success"
  }
}
```

## Sample Rate

This example uses a 10% sample rate for successful authentication events:
```go
audit := apikeys.NewStructuredAuditLogger(
    logger.Named("audit"),
    0.1,  // 10% sampling
    true, // Log success events
)
```

Failed authentication attempts are **always logged** regardless of sample rate.

## Configuration

Key configuration points:
- `Namespace`: "example" - used as prefix for all metrics
- `Sample Rate`: 0.1 (10%) - only 10% of successful auth events are logged
- `Log Success`: true - enables logging of successful authentications
- `Tracing`: nil - no distributed tracing in this example

## Production Considerations

For production use:

1. **Replace in-memory storage** with Redis or another persistent backend
2. **Adjust sample rate** based on traffic (higher traffic = lower rate)
3. **Enable tracing** for distributed systems
4. **Secure metrics endpoint** - consider authentication or firewall rules
5. **Use production logger config** - see `zap.NewProduction()`
6. **Configure log aggregation** - ship logs to Elasticsearch, Splunk, etc.
7. **Set up alerting** - monitor auth failure rate, latency, etc.

## Next Steps

- See `../prometheus/` for full Prometheus + Grafana setup
- See `../compliance-soc2/` for SOC 2 compliance mode
- See `../custom-provider/` for custom metrics providers
