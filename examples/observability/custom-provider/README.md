# Custom Provider Example

Demonstrates implementing custom observability providers for integration with DataDog, StatsD, Elasticsearch, Splunk, or any other metrics/audit backend.

## Features

✅ Custom metrics provider (easily adapt for DataDog, StatsD, CloudWatch)
✅ Custom audit provider (easily adapt for Elasticsearch, Splunk, Sumo Logic)
✅ Complete provider interface implementation
✅ Integration examples in comments

## Quick Start

```bash
go run main.go
```

Watch the logs for `METRIC:` and `AUDIT:` events.

## Custom Providers

### Metrics Provider

Implements `MetricsProvider` interface:
- `RecordAuthAttempt()` - Authentication attempts
- `RecordAuthSuccess()` - Successful authentications
- `RecordAuthError()` - Failed authentications
- `RecordAuthDuration()` - Auth latency
- `RecordOperation()` - CRUD operations
- `RecordCacheHit/Miss/Eviction()` - Cache events
- `RecordActiveKeys()` - Active key count

### Audit Provider

Implements `AuditProvider` interface:
- `LogAuthAttempt()` - Authentication events
- `LogKeyCreated()` - Key creation with state
- `LogKeyUpdated()` - Key updates with before/after
- `LogKeyDeleted()` - Key deletion with state
- `LogKeyAccessed()` - Key access events
- `LogSecurityEvent()` - Security incidents

## Integration Examples

### DataDog

```go
import "github.com/DataDog/datadog-go/statsd"

type DataDogMetricsProvider struct {
    client *statsd.Client
}

func (m *DataDogMetricsProvider) RecordAuthAttempt(ctx context.Context, labels map[string]string) {
    tags := []string{
        "org_id:" + labels["org_id"],
        "endpoint:" + labels["endpoint"],
    }
    m.client.Incr("apikeys.auth.attempts", tags, 1)
}
```

### StatsD

```go
import "github.com/cactus/go-statsd-client/statsd"

func (m *StatsDMetricsProvider) RecordAuthDuration(ctx context.Context, labels map[string]string, duration time.Duration) {
    m.client.Timing("apikeys.auth.duration", duration.Milliseconds(), 1.0)
}
```

### Elasticsearch

```go
import "github.com/elastic/go-elasticsearch/v8"

type ElasticsearchAuditProvider struct {
    client *elasticsearch.Client
}

func (a *ElasticsearchAuditProvider) LogAuthAttempt(event *apikeys.AuditEvent) {
    body, _ := json.Marshal(event)
    a.client.Index("audit-logs", bytes.NewReader(body))
}
```

### Splunk

```go
import "github.com/splunk/splunk-cloud-sdk-go/services/ingest"

func (a *SplunkAuditProvider) LogKeyCreated(event *apikeys.AuditEvent) {
    a.client.SendEvent(&ingest.Event{
        Body: event,
        Source: "go-apikeys",
        Sourcetype: "audit:json",
    })
}
```

## Production Implementation

1. **Replace stdout logging** with actual backend clients
2. **Handle errors** - implement retry logic, circuit breakers
3. **Add buffering** - batch metrics/logs for efficiency
4. **Configure timeouts** - prevent blocking on backend failures
5. **Monitor providers** - track provider health, latency
6. **Implement fallbacks** - queue to disk if backend unavailable

## Example: Full DataDog Integration

```go
package main

import (
    "context"
    "time"
    "github.com/DataDog/datadog-go/statsd"
    apikeys "github.com/vaudience/go-apikeys/v2"
)

type DataDogProvider struct {
    client *statsd.Client
}

func NewDataDogProvider(addr string) (*DataDogProvider, error) {
    client, err := statsd.New(addr)
    if err != nil {
        return nil, err
    }
    return &DataDogProvider{client: client}, nil
}

func (d *DataDogProvider) RecordAuthAttempt(ctx context.Context, labels map[string]string) {
    tags := []string{
        "org:" + labels["org_id"],
        "endpoint:" + labels["endpoint"],
    }
    d.client.Incr("apikeys.auth.attempts", tags, 1)
}

// ... implement other methods ...

func main() {
    ddProvider, _ := NewDataDogProvider("127.0.0.1:8125")
    obs := apikeys.NewObservability(ddProvider, nil, nil)
    service.SetObservability(obs)
}
```

## Next Steps

- Adapt providers for your infrastructure
- Add error handling and retries
- Implement buffering for high-throughput
- Set up alerting on provider failures
- Monitor provider performance
