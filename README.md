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

### Basic Configuration

The receiver uses a single HTTP server for all data types:

```yaml
receivers:
  vercel:
    endpoint: "0.0.0.0:8080"  # Single endpoint for all drain types
    secret: "your-secret-key"  # Default secret for all endpoints
```

### Advanced Configuration

You can customize routes and secrets per signal type:

```yaml
receivers:
  vercel:
    endpoint: "0.0.0.0:8080"
    secret: "default-secret-key"  # Default secret for all endpoints

    # Optional per-signal overrides
    logs:
      route: "/custom-logs"      # Override default /logs route
      secret: "logs-secret"       # Override default secret for logs only

    traces:
      route: "/custom-traces"     # Override default /traces route

    speed_insights:
      secret: "metrics-secret"    # Override secret only (keeps default /speed-insights route)

    web_analytics:
      # Uses defaults: route=/analytics, secret from top-level
```

### Configuration Fields

#### Top-Level Fields

- `endpoint` (optional): Host and port to listen on. Default: `:8080`
- `secret` (optional): Default secret for x-vercel-signature header verification. If not provided, signature verification is disabled for all endpoints unless overridden per signal.

#### Per-Signal Fields (logs, traces, speed_insights, web_analytics)

Each signal type supports optional overrides:

- `route` (optional): Custom HTTP route for this signal type. If not provided, defaults are:
  - Logs: `/logs`
  - Traces: `/traces`
  - Speed Insights: `/speed-insights`
  - Web Analytics: `/analytics`
- `secret` (optional): Secret specific to this signal type. Overrides the top-level `secret` if provided.

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
curl -X POST http://localhost:8080/traces \
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
curl -X POST http://localhost:8080/speed-insights \
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

The receiver uses a unified architecture:

- **Single HTTP Server**: Manages all endpoints on one port (default :8080)
- **Shared Receiver**: One receiver instance handles all signal types (logs, traces, metrics, analytics)
- **Authentication**: Signature verification with default secret and per-signal overrides
- **Flexible Routing**: Configurable routes per signal type with sensible defaults
- **Schema Conversion**: Converts Vercel data formats to OpenTelemetry data models

## Example Configurations

### Minimal Setup (No Authentication)

```yaml
receivers:
  vercel:
    # Uses all defaults: endpoint :8080, no authentication, default routes
```

### Simple Setup (One Secret for All)

```yaml
receivers:
  vercel:
    endpoint: "0.0.0.0:8080"
    secret: "my-shared-secret"
```

### Per-Environment Secrets

```yaml
receivers:
  vercel:
    endpoint: "0.0.0.0:8080"
    secret: "default-secret"

    logs:
      secret: "logs-only-secret"

    traces:
      secret: "traces-only-secret"
```

### Custom Routes with Authentication

```yaml
receivers:
  vercel:
    endpoint: "0.0.0.0:8080"
    secret: "shared-secret"

    logs:
      route: "/v1/logs"

    traces:
      route: "/v1/traces"
      secret: "traces-specific-secret"

    speed_insights:
      route: "/v1/metrics"

    web_analytics:
      route: "/v1/analytics"
```

## License

This receiver is part of the Lawrence project.

