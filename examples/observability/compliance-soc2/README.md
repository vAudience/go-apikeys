# SOC 2 Type II Compliance Example

Demonstrates compliance-focused audit logging meeting SOC 2 Type II requirements.

## SOC 2 Requirements Met

✅ **100% Audit Sampling** - All operations logged, no sampling
✅ **Actor Attribution** - Complete who/what/when/where tracking
✅ **State Capture** - Before/after states for all modifications
✅ **Tamper-Evident Logs** - Structured JSON with timestamps and event IDs
✅ **Retention Ready** - 1-year minimum retention supported

## Quick Start

```bash
go run main.go
```

## Compliance Mode Features

When `SetComplianceMode(ComplianceSOC2)` is enabled:
- Sample rate is enforced to 1.0 (100%)
- All success events are logged
- All failure events are logged
- Complete actor tracking (user_id, org_id, IP, user agent)
- Before/after state capture for all CRUD operations

## Audit Log Format

Every operation generates a structured audit event:

```json
{
  "level": "info",
  "timestamp": "2025-01-15T10:30:00Z",
  "message": "AUDIT_EVENT",
  "event_type": "key.created",
  "event": {
    "event_id": "unique-uuid",
    "event_type": "key.created",
    "timestamp": "2025-01-15T10:30:00Z",
    "actor": {
      "user_id": "admin-user",
      "org_id": "admin-org",
      "api_key_hash": "sha3-512-hash",
      "ip_address": "192.168.1.100",
      "user_agent": "MyApp/1.0"
    },
    "resource": {
      "type": "api_key",
      "id": "key-hash",
      "name": "Production API Key"
    },
    "outcome": "success",
    "operation": "create",
    "target_user_id": "new-user",
    "target_org_id": "customer-org",
    "after_state": {
      "api_key_hash": "hash",
      "user_id": "new-user",
      "org_id": "customer-org",
      "name": "Production API Key"
    }
  }
}
```

## Testing

```bash
# Make authenticated request (generates audit log)
curl -H "X-API-Key: soc2_xxx..." http://localhost:8080/api/data

# Try invalid key (generates failure audit log)
curl -H "X-API-Key: invalid" http://localhost:8080/api/data
```

## Log Aggregation

For production SOC 2 compliance:

1. **Ship logs to SIEM** (Splunk, Elasticsearch, etc.)
2. **Enable log retention** (minimum 1 year)
3. **Implement log integrity** (checksums, write-once storage)
4. **Set up alerting** (suspicious patterns, unauthorized access)
5. **Regular audits** (review logs quarterly)

## Production Setup

```go
// Configure log shipping
logger := zap.New(
    zapcore.NewCore(
        zapcore.NewJSONEncoder(config),
        zapcore.AddSync(logShipper), // Your SIEM shipper
        zapcore.InfoLevel,
    ),
)

// Enable compliance mode
audit := apikeys.NewStructuredAuditLogger(logger.Named("audit"), 1.0, true)
audit.SetComplianceMode(apikeys.ComplianceSOC2)

// Verify settings
fmt.Printf("Sample Rate: %f (must be 1.0)\n", audit.GetSampleRate())
fmt.Printf("Log Success: %v (must be true)\n", audit.GetLogSuccess())
```

## Compliance Modes Available

- `ComplianceSOC2` - SOC 2 Type II
- `CompliancePCIDSS` - PCI-DSS
- `ComplianceGDPR` - GDPR (with PII minimization)
- `ComplianceHIPAA` - HIPAA (6-year retention)

## Next Steps

- Set up log aggregation (Elasticsearch, Splunk)
- Configure 1-year+ log retention
- Implement log integrity verification
- Set up SOC 2 audit dashboard
- Document audit log format for auditors
