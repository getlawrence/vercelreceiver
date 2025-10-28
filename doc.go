// Package vercelreceiver implements an OpenTelemetry Collector receiver for Vercel Drains.
//
// The Vercel receiver accepts observability data from Vercel's drain system via HTTP endpoints.
// It supports logs, traces (OTLP), speed insights (metrics), and web analytics data.
//
// # Configuration
//
// The receiver uses a unified configuration with a single HTTP endpoint for all data types.
// By default, it listens on port 8080 and exposes the following routes:
//   - POST /logs          - Receives log drain data
//   - POST /traces        - Receives trace drain data (OTLP JSON or Protobuf)
//   - POST /speed-insights - Receives speed insights/web vitals data
//   - POST /analytics     - Receives web analytics events
//   - GET  /health        - Health check endpoint
//
// Basic configuration example:
//
//	receivers:
//	  vercel:
//	    endpoint: "0.0.0.0:8080"
//	    secret: "your-secret-key"
//
// Advanced configuration with per-signal overrides:
//
//	receivers:
//	  vercel:
//	    endpoint: "0.0.0.0:8080"
//	    secret: "default-secret"
//	    logs:
//	      route: "/custom-logs"
//	      secret: "logs-specific-secret"
//	    traces:
//	      route: "/custom-traces"
//	    speed_insights:
//	      secret: "metrics-secret"
//	    web_analytics:
//	      # Uses defaults
//
// # Authentication
//
// The receiver supports Vercel's signature verification using the x-vercel-signature header.
// Signatures are computed using HMAC-SHA256. Authentication can be configured globally
// or per signal type. If no secret is configured, signature verification is disabled.
//
// # Data Formats
//
// The receiver accepts multiple data formats:
//   - Logs: JSON array or NDJSON (newline-delimited JSON)
//   - Traces: OTLP JSON or OTLP Protobuf
//   - Speed Insights: JSON array or NDJSON
//   - Web Analytics: JSON array or NDJSON
//
// All data is converted to OpenTelemetry's internal data model (pdata) before being
// passed to the configured consumers.
package vercelreceiver
