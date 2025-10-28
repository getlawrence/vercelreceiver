# Vercel Drains Receiver

OpenTelemetry Collector receiver for receiving observability data from Vercel Drains.

## Overview

This receiver accepts logs, traces, speed insights, and web analytics data from Vercel's drain system via HTTP endpoints. It supports signature verification for security and multiple data formats.

## Supported Data Types

- **Logs**: Runtime, build, and static logs from Vercel deployments
- **Traces**: Distributed tracing data using OpenTelemetry Protocol (OTLP)
- **Speed Insights**: Performance metrics and web vitals
- **Web Analytics**: Page views and custom events

## Configuration

```yaml
receivers:
  vercel:
    logs:
      endpoint: "0.0.0.0:8080"
      secret: "your-secret-key"
    traces:
      endpoint: "0.0.0.0:8081"
      secret: "your-secret-key"
    speed_insights:
      endpoint: "0.0.0.0:8082"
      secret: "your-secret-key"
    web_analytics:
      endpoint: "0.0.0.0:8083"
      secret: "your-secret-key"
```

### Configuration Fields

- `endpoint` (optional): Host and port to listen on (default: `:8080`)
- `secret` (optional): Secret for x-vercel-signature header verification. If not provided, signature verification is disabled.

## Endpoints

The receiver exposes the following HTTP endpoints:

- **POST /logs** - Receives log drain data
- **POST /traces** - Receives trace drain data
- **POST /speed-insights** - Receives speed insights data
- **POST /analytics** - Receives web analytics data
- **GET /health** - Health check endpoint

## Vercel Configuration

Configure your Vercel drains to send data to these endpoints:

### Logs Drain

```
Endpoint URL: https://your-collector-domain.com/logs
Format: JSON or NDJSON
Secret: your-secret-key (optional)
```

### Traces Drain

```
Endpoint URL: https://your-collector-domain.com/traces
Format: JSON or Protobuf
Secret: your-secret-key (optional)
```

### Speed Insights Drain

```
Endpoint URL: https://your-collector-domain.com/speed-insights
Format: JSON or NDJSON
Secret: your-secret-key (optional)
```

### Web Analytics Drain

```
Endpoint URL: https://your-collector-domain.com/analytics
Format: JSON or NDJSON
Secret: your-secret-key (optional)
```

## Signature Verification

The receiver supports Vercel's signature verification using the `x-vercel-signature` header. The signature is computed using HMAC-SHA256:

```go
secret := []byte("your-secret-key")
mac := hmac.New(sha256.New, secret)
mac.Write(bodyBytes)
signature := hex.EncodeToString(mac.Sum(nil))
```

If no secret is configured, signature verification is skipped.

## Data Formats

### Logs

Supports both JSON array and NDJSON (newline-delimited JSON) formats.

**JSON Array Format:**
```json
[
  {
    "id": "1573817187330377061717300000",
    "deploymentId": "dpl_233NRGRjVZX1caZrXWtz5g1TAksD",
    "source": "build",
    "host": "my-app-abc123.vercel.app",
    "timestamp": 1573817187330,
    "level": "info",
    "message": "Build completed successfully"
  }
]
```

**NDJSON Format:**
```
{"id": "1573817187330377061717300000","deploymentId": "dpl_233NRGRjVZX1caZrXWtz5g1TAksD","source": "build","host": "my-app-abc123.vercel.app","timestamp": 1573817187330,"level": "info","message": "Build completed successfully"}
```

### Traces

Supports JSON and Protobuf formats following the OpenTelemetry Protocol (OTLP) specification.

**JSON Format:**
```json
{
  "resourceSpans": [{
    "resource": {
      "attributes": [{
        "key": "vercel.projectId",
        "value": {"stringValue": "Qmc52npNy86S8VV4Mt8a8dP1LEkRNbgosW3pBCQytkcgf2"}
      }]
    },
    "scopeSpans": [{
      "scope": {"name": "vercel"},
      "spans": [{
        "traceId": "7bba9f33312b3dbb8b2c2c62bb7abe2d",
        "spanId": "086e83747d0e381e",
        "name": "GET /api/users",
        "kind": "server"
      }]
    }]
  }]
}
```

### Speed Insights

Converts web vitals (CLS, LCP, FID, FCP, TTFB, INP) to OpenTelemetry metrics.

### Web Analytics

Converts pageviews and custom events to OpenTelemetry logs with event attributes.

## Testing

### Test Logs Endpoint

```bash
curl -X POST http://localhost:8080/logs \
  -H "Content-Type: application/json" \
  -H "x-vercel-signature: your-signature" \
  -d '[
    {
      "id": "test123",
      "deploymentId": "dpl_test",
      "source": "build",
      "host": "test.vercel.app",
      "timestamp": 1573817187330,
      "level": "info",
      "message": "Test log message",
      "projectId": "proj_test"
    }
  ]'
```

### Test Traces Endpoint

```bash
curl -X POST http://localhost:8081/traces \
  -H "Content-Type: application/json" \
  -H "x-vercel-signature: your-signature" \
  -d '{
    "resourceSpans": [{
      "resource": {"attributes": []},
      "scopeSpans": [{
        "scope": {"name": "test"},
        "spans": [{
          "traceId": "7bba9f33312b3dbb8b2c2c62bb7abe2d",
          "spanId": "086e83747d0e381e",
          "name": "test_span"
        }]
      }]
    }]
  }'
```

### Test Speed Insights Endpoint

```bash
curl -X POST http://localhost:8082/speed-insights \
  -H "Content-Type: application/json" \
  -H "x-vercel-signature: your-signature" \
  -d '[{
    "schema": "vercel.speed_insights.v1",
    "timestamp": "2023-09-14T15:30:00.000Z",
    "metricType": "LCP",
    "value": 2.5
  }]'
```

## Architecture

The receiver consists of:

- **HTTP Server**: Manages all endpoints and routing
- **Authentication**: Signature verification middleware
- **Receivers**: Separate receivers for logs, traces, metrics, and analytics
- **Schema Conversion**: Converts Vercel data formats to OpenTelemetry data models

## License

This receiver is part of the Lawrence project.

