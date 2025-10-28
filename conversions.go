package vercelreceiver

import (
	"fmt"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

// convertVercelLogsToPdata converts Vercel logs to OpenTelemetry pdata.Logs
func convertVercelLogsToPdata(logs []vercelLog) plog.Logs {
	pLogs := plog.NewLogs()
	rl := pLogs.ResourceLogs().AppendEmpty()

	for _, log := range logs {
		scopeLogs := rl.ScopeLogs().AppendEmpty()
		lr := scopeLogs.LogRecords().AppendEmpty()

		// Set timestamp
		lr.SetTimestamp(pcommon.NewTimestampFromTime(time.Unix(0, log.Timestamp*int64(time.Millisecond))))

		// Set severity
		switch log.Level {
		case "info":
			lr.SetSeverityNumber(plog.SeverityNumberInfo)
			lr.SetSeverityText("INFO")
		case "warning", "warn":
			lr.SetSeverityNumber(plog.SeverityNumberWarn)
			lr.SetSeverityText("WARN")
		case "error":
			lr.SetSeverityNumber(plog.SeverityNumberError)
			lr.SetSeverityText("ERROR")
		case "fatal":
			lr.SetSeverityNumber(plog.SeverityNumberFatal)
			lr.SetSeverityText("FATAL")
		default:
			lr.SetSeverityNumber(plog.SeverityNumberUnspecified)
			lr.SetSeverityText(log.Level)
		}

		// Set body
		body := pcommon.NewValueStr(log.Message)
		body.CopyTo(lr.Body())

		// Set attributes
		attrs := lr.Attributes()
		if log.ID != "" {
			attrs.PutStr("log.id", log.ID)
		}
		if log.DeploymentID != "" {
			attrs.PutStr("deployment.id", log.DeploymentID)
		}
		if log.Source != "" {
			attrs.PutStr("source", log.Source)
		}
		if log.Host != "" {
			attrs.PutStr("host", log.Host)
		}
		if log.ProjectID != "" {
			attrs.PutStr("project.id", log.ProjectID)
		}
		if log.BuildID != "" {
			attrs.PutStr("build.id", log.BuildID)
		}
		if log.Entrypoint != "" {
			attrs.PutStr("entrypoint", log.Entrypoint)
		}
		if log.Destination != "" {
			attrs.PutStr("destination", log.Destination)
		}
		if log.Path != "" {
			attrs.PutStr("path", log.Path)
		}
		if log.Type != "" {
			attrs.PutStr("type", log.Type)
		}
		if log.StatusCode != 0 {
			attrs.PutInt("status.code", int64(log.StatusCode))
		}
		if log.RequestID != "" {
			attrs.PutStr("request.id", log.RequestID)
		}
		if log.Environment != "" {
			attrs.PutStr("environment", log.Environment)
		}
		if log.Branch != "" {
			attrs.PutStr("branch", log.Branch)
		}
		if log.JA3Digest != "" {
			attrs.PutStr("ja3.digest", log.JA3Digest)
		}
		if log.JA4Digest != "" {
			attrs.PutStr("ja4.digest", log.JA4Digest)
		}
		if log.EdgeType != "" {
			attrs.PutStr("edge.type", log.EdgeType)
		}
		if log.ProjectName != "" {
			attrs.PutStr("project.name", log.ProjectName)
		}
		if log.ExecutionRegion != "" {
			attrs.PutStr("execution.region", log.ExecutionRegion)
		}
		if log.TraceID != "" {
			lr.SetTraceID(parseTraceID(log.TraceID))
		} else if log.TraceIDAlt != "" {
			lr.SetTraceID(parseTraceID(log.TraceIDAlt))
		}
		if log.SpanID != "" {
			lr.SetSpanID(parseSpanID(log.SpanID))
		} else if log.SpanIDAlt != "" {
			lr.SetSpanID(parseSpanID(log.SpanIDAlt))
		}

		// Handle proxy data
		if log.Proxy != nil {
			if log.Proxy.Timestamp != 0 {
				attrs.PutInt("proxy.timestamp", log.Proxy.Timestamp)
			}
			if log.Proxy.Method != "" {
				attrs.PutStr("proxy.method", log.Proxy.Method)
			}
			if log.Proxy.Host != "" {
				attrs.PutStr("proxy.host", log.Proxy.Host)
			}
			if log.Proxy.Path != "" {
				attrs.PutStr("proxy.path", log.Proxy.Path)
			}
			if len(log.Proxy.UserAgent) > 0 {
				attrs.PutStr("proxy.user.agent", log.Proxy.UserAgent[0])
			}
			if log.Proxy.Region != "" {
				attrs.PutStr("proxy.region", log.Proxy.Region)
			}
			if log.Proxy.Referer != "" {
				attrs.PutStr("proxy.referer", log.Proxy.Referer)
			}
			if log.Proxy.StatusCode != 0 {
				attrs.PutInt("proxy.status.code", int64(log.Proxy.StatusCode))
			}
			if log.Proxy.ClientIP != "" {
				attrs.PutStr("proxy.client.ip", log.Proxy.ClientIP)
			}
			if log.Proxy.Scheme != "" {
				attrs.PutStr("proxy.scheme", log.Proxy.Scheme)
			}
			if log.Proxy.ResponseByteSize != 0 {
				attrs.PutInt("proxy.response.byte.size", log.Proxy.ResponseByteSize)
			}
			if log.Proxy.CacheID != "" {
				attrs.PutStr("proxy.cache.id", log.Proxy.CacheID)
			}
			if log.Proxy.PathType != "" {
				attrs.PutStr("proxy.path.type", log.Proxy.PathType)
			}
			if log.Proxy.PathTypeVariant != "" {
				attrs.PutStr("proxy.path.type.variant", log.Proxy.PathTypeVariant)
			}
			if log.Proxy.VercelID != "" {
				attrs.PutStr("proxy.vercel.id", log.Proxy.VercelID)
			}
			if log.Proxy.VercelCache != "" {
				attrs.PutStr("proxy.vercel.cache", log.Proxy.VercelCache)
			}
			if log.Proxy.LambdaRegion != "" {
				attrs.PutStr("proxy.lambda.region", log.Proxy.LambdaRegion)
			}
			if log.Proxy.WAFAction != "" {
				attrs.PutStr("proxy.waf.action", log.Proxy.WAFAction)
			}
			if log.Proxy.WAFRuleID != "" {
				attrs.PutStr("proxy.waf.rule.id", log.Proxy.WAFRuleID)
			}
		}
	}

	return pLogs
}

// parseTraceID parses a trace ID string to pdata.TraceID
func parseTraceID(idStr string) pcommon.TraceID {
	var traceID pcommon.TraceID
	copy(traceID[:], []byte(idStr))
	return traceID
}

// parseSpanID parses a span ID string to pdata.SpanID
func parseSpanID(idStr string) pcommon.SpanID {
	var spanID pcommon.SpanID
	copy(spanID[:], []byte(idStr))
	return spanID
}

// convertSpeedInsightsToPdata converts Speed Insights data to OpenTelemetry pdata.Metrics
func convertSpeedInsightsToPdata(insights []speedInsight) pmetric.Metrics {
	metrics := pmetric.NewMetrics()

	// Group by resource attributes first
	rmMap := make(map[string]pmetric.ResourceMetrics)
	metricMap := make(map[string]pmetric.Metric)

	for _, insight := range insights {
		// Create resource key from attributes that define the resource
		resourceKey := fmt.Sprintf("%s|%s|%d|%s|%s|%s|%s|%s|%s|%s|%s",
			insight.ProjectID, insight.OwnerID, insight.DeviceID, insight.Origin,
			insight.Country, insight.Region, insight.City, insight.OSName,
			insight.ClientName, insight.DeviceType, insight.DeploymentID)

		// Get or create ResourceMetrics
		rm, exists := rmMap[resourceKey]
		if !exists {
			rm = metrics.ResourceMetrics().AppendEmpty()

			// Add resource attributes
			res := rm.Resource()
			if insight.ProjectID != "" {
				res.Attributes().PutStr("project.id", insight.ProjectID)
			}
			if insight.OwnerID != "" {
				res.Attributes().PutStr("owner.id", insight.OwnerID)
			}
			if insight.DeviceID != 0 {
				res.Attributes().PutInt("device.id", insight.DeviceID)
			}
			if insight.Origin != "" {
				res.Attributes().PutStr("origin", insight.Origin)
			}
			if insight.Country != "" {
				res.Attributes().PutStr("country", insight.Country)
			}
			if insight.Region != "" {
				res.Attributes().PutStr("region", insight.Region)
			}
			if insight.City != "" {
				res.Attributes().PutStr("city", insight.City)
			}
			if insight.OSName != "" {
				res.Attributes().PutStr("os.name", insight.OSName)
			}
			if insight.ClientName != "" {
				res.Attributes().PutStr("client.name", insight.ClientName)
			}
			if insight.DeviceType != "" {
				res.Attributes().PutStr("device.type", insight.DeviceType)
			}
			if insight.DeploymentID != "" {
				res.Attributes().PutStr("deployment.id", insight.DeploymentID)
			}

			rmMap[resourceKey] = rm
		}

		// Get or create metric within this resource metrics
		metricName := fmt.Sprintf("vercel.speed_insights.%s", insight.MetricType)
		fullMetricKey := fmt.Sprintf("%s|%s", resourceKey, metricName)

		metric, exists := metricMap[fullMetricKey]
		if !exists {
			// Get or create scope metrics for this resource
			var sm pmetric.ScopeMetrics
			if rm.ScopeMetrics().Len() == 0 {
				sm = rm.ScopeMetrics().AppendEmpty()
			} else {
				sm = rm.ScopeMetrics().At(0)
			}

			metric = sm.Metrics().AppendEmpty()
			metric.SetName(metricName)
			metric.SetDescription(fmt.Sprintf("Vercel Speed Insights metric: %s", insight.MetricType))
			metric.SetUnit(metricTypeToUnit(insight.MetricType))

			metricMap[fullMetricKey] = metric
		}

		// Create gauge data point
		gauge := metric.SetEmptyGauge()
		dp := gauge.DataPoints().AppendEmpty()

		// Set timestamp
		if ts, err := time.Parse(time.RFC3339, insight.Timestamp); err == nil {
			dp.SetTimestamp(pcommon.NewTimestampFromTime(ts))
		} else {
			dp.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))
		}

		// Set value
		dp.SetDoubleValue(insight.Value)

		// Set attributes
		attrs := dp.Attributes()
		if insight.Path != "" {
			attrs.PutStr("path", insight.Path)
		}
		if insight.Route != "" {
			attrs.PutStr("route", insight.Route)
		}
		if insight.OSVersion != "" {
			attrs.PutStr("os.version", insight.OSVersion)
		}
		if insight.ClientVersion != "" {
			attrs.PutStr("client.version", insight.ClientVersion)
		}
		if insight.DeviceBrand != "" {
			attrs.PutStr("device.brand", insight.DeviceBrand)
		}
		if insight.ConnectionSpeed != "" {
			attrs.PutStr("connection.speed", insight.ConnectionSpeed)
		}
		if insight.BrowserEngine != "" {
			attrs.PutStr("browser.engine", insight.BrowserEngine)
		}
		if insight.SDKVersion != "" {
			attrs.PutStr("sdk.version", insight.SDKVersion)
		}
		if insight.VercelEnvironment != "" {
			attrs.PutStr("vercel.environment", insight.VercelEnvironment)
		}
		if insight.VercelURL != "" {
			attrs.PutStr("vercel.url", insight.VercelURL)
		}
	}

	return metrics
}

// metricTypeToUnit returns the unit for a metric type
func metricTypeToUnit(metricType string) string {
	switch metricType {
	case "CLS", "FCP", "LCP", "TTFB", "INP":
		return "1" // Dimensionless score
	case "FID":
		return "ms" // Milliseconds
	default:
		return "1"
	}
}

// convertWebAnalyticsToPdata converts Web Analytics events to OpenTelemetry pdata.Logs
func convertWebAnalyticsToPdata(events []webAnalyticsEvent) plog.Logs {
	pLogs := plog.NewLogs()
	rl := pLogs.ResourceLogs().AppendEmpty()
	scopeLogs := rl.ScopeLogs().AppendEmpty()

	for _, event := range events {
		lr := scopeLogs.LogRecords().AppendEmpty()

		// Set timestamp
		lr.SetTimestamp(pcommon.NewTimestampFromTime(time.Unix(0, event.Timestamp*int64(time.Millisecond))))

		// Set severity
		lr.SetSeverityNumber(plog.SeverityNumberInfo)
		lr.SetSeverityText("INFO")

		// Set body
		body := pcommon.NewValueStr(event.EventName)
		if body.AsString() == "" {
			body = pcommon.NewValueStr(event.EventType)
		}
		body.CopyTo(lr.Body())

		// Set attributes
		attrs := lr.Attributes()
		attrs.PutStr("event.type", event.EventType)
		if event.EventName != "" {
			attrs.PutStr("event.name", event.EventName)
		}
		if event.EventData != "" {
			attrs.PutStr("event.data", event.EventData)
		}
		if event.DataSourceName != "" {
			attrs.PutStr("data.source.name", event.DataSourceName)
		}
		if event.SessionID != 0 {
			attrs.PutInt("session.id", event.SessionID)
		}
		if event.Origin != "" {
			attrs.PutStr("origin", event.Origin)
		}
		if event.Path != "" {
			attrs.PutStr("path", event.Path)
		}
		if event.Referrer != "" {
			attrs.PutStr("referrer", event.Referrer)
		}
		if event.QueryParams != "" {
			attrs.PutStr("query.params", event.QueryParams)
		}
		if event.Route != "" {
			attrs.PutStr("route", event.Route)
		}
		if event.City != "" {
			attrs.PutStr("city", event.City)
		}
		if event.OSName != "" {
			attrs.PutStr("os.name", event.OSName)
		}
		if event.OSVersion != "" {
			attrs.PutStr("os.version", event.OSVersion)
		}
		if event.ClientName != "" {
			attrs.PutStr("client.name", event.ClientName)
		}
		if event.ClientType != "" {
			attrs.PutStr("client.type", event.ClientType)
		}
		if event.ClientVersion != "" {
			attrs.PutStr("client.version", event.ClientVersion)
		}
		if event.DeviceType != "" {
			attrs.PutStr("device.type", event.DeviceType)
		}
		if event.DeviceBrand != "" {
			attrs.PutStr("device.brand", event.DeviceBrand)
		}
		if event.DeviceModel != "" {
			attrs.PutStr("device.model", event.DeviceModel)
		}
		if event.BrowserEngine != "" {
			attrs.PutStr("browser.engine", event.BrowserEngine)
		}
		if event.BrowserEngineVersion != "" {
			attrs.PutStr("browser.engine.version", event.BrowserEngineVersion)
		}
		if event.SDKVersion != "" {
			attrs.PutStr("sdk.version", event.SDKVersion)
		}
		if event.SDKName != "" {
			attrs.PutStr("sdk.name", event.SDKName)
		}
		if event.VercelEnvironment != "" {
			attrs.PutStr("vercel.environment", event.VercelEnvironment)
		}
		if event.VercelURL != "" {
			attrs.PutStr("vercel.url", event.VercelURL)
		}
		if event.Flags != "" {
			attrs.PutStr("flags", event.Flags)
		}
		if event.Deployment != "" {
			attrs.PutStr("deployment.id", event.Deployment)
		}
	}

	return pLogs
}
