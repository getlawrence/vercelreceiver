package vercelreceiver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/receiverhelper"
	"go.uber.org/zap"
)

// vercelLog represents a Vercel log entry
type vercelLog struct {
	ID              string       `json:"id"`
	DeploymentID    string       `json:"deploymentId"`
	Source          string       `json:"source"`
	Host            string       `json:"host"`
	Timestamp       int64        `json:"timestamp"`
	ProjectID       string       `json:"projectId"`
	Level           string       `json:"level"`
	Message         string       `json:"message"`
	BuildID         string       `json:"buildId,omitempty"`
	Entrypoint      string       `json:"entrypoint,omitempty"`
	Destination     string       `json:"destination,omitempty"`
	Path            string       `json:"path,omitempty"`
	Type            string       `json:"type,omitempty"`
	StatusCode      int          `json:"statusCode,omitempty"`
	RequestID       string       `json:"requestId,omitempty"`
	Environment     string       `json:"environment,omitempty"`
	Branch          string       `json:"branch,omitempty"`
	JA3Digest       string       `json:"ja3Digest,omitempty"`
	JA4Digest       string       `json:"ja4Digest,omitempty"`
	EdgeType        string       `json:"edgeType,omitempty"`
	ProjectName     string       `json:"projectName,omitempty"`
	ExecutionRegion string       `json:"executionRegion,omitempty"`
	TraceID         string       `json:"traceId,omitempty"`
	SpanID          string       `json:"spanId,omitempty"`
	TraceIDAlt      string       `json:"trace.id,omitempty"`
	SpanIDAlt       string       `json:"span.id,omitempty"`
	Proxy           *vercelProxy `json:"proxy,omitempty"`
}

type vercelProxy struct {
	Timestamp        int64    `json:"timestamp"`
	Method           string   `json:"method"`
	Host             string   `json:"host"`
	Path             string   `json:"path"`
	UserAgent        []string `json:"userAgent"`
	Region           string   `json:"region"`
	Referer          string   `json:"referer,omitempty"`
	StatusCode       int      `json:"statusCode,omitempty"`
	ClientIP         string   `json:"clientIp,omitempty"`
	Scheme           string   `json:"scheme,omitempty"`
	ResponseByteSize int64    `json:"responseByteSize,omitempty"`
	CacheID          string   `json:"cacheId,omitempty"`
	PathType         string   `json:"pathType,omitempty"`
	PathTypeVariant  string   `json:"pathTypeVariant,omitempty"`
	VercelID         string   `json:"vercelId,omitempty"`
	VercelCache      string   `json:"vercelCache,omitempty"`
	LambdaRegion     string   `json:"lambdaRegion,omitempty"`
	WAFAction        string   `json:"wafAction,omitempty"`
	WAFRuleID        string   `json:"wafRuleId,omitempty"`
}

// logsReceiver handles Vercel log drain data
type logsReceiver struct {
	logger   *zap.Logger
	consumer consumer.Logs
	server   *httpServer
	wg       *sync.WaitGroup
	obsrecv  *receiverhelper.ObsReport
}

// newLogsReceiver creates a new logs receiver
func newLogsReceiver(params receiver.Settings, cfg *Config, consumer consumer.Logs) (*logsReceiver, error) {
	obsrecv, err := receiverhelper.NewObsReport(receiverhelper.ObsReportSettings{
		ReceiverID:             params.ID,
		Transport:              "http",
		ReceiverCreateSettings: params,
	})
	if err != nil {
		return nil, err
	}

	r := &logsReceiver{
		logger:   params.Logger,
		consumer: consumer,
		wg:       &sync.WaitGroup{},
		obsrecv:  obsrecv,
	}

	server := newHTTPServer(cfg, params.Logger)
	server.logsHandler = r.handleLogs
	r.server = server

	return r, nil
}

// Start starts the logs receiver
func (r *logsReceiver) Start(ctx context.Context, host component.Host) error {
	return r.server.start()
}

// Shutdown stops the logs receiver
func (r *logsReceiver) Shutdown(ctx context.Context) error {
	r.logger.Debug("Shutting down server")
	err := r.server.shutdown(ctx)
	if err != nil {
		return err
	}
	r.logger.Debug("Waiting for shutdown to complete.")
	r.wg.Wait()
	return nil
}

// handleLogs processes incoming log drain requests
func (r *logsReceiver) handleLogs(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		r.logger.Error("Failed to read request body", zap.Error(err))
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	req.Body.Close()

	// Verify signature if secret is configured (for tests that call handler directly)
	if r.server.cfg.Logs.Secret != "" {
		if err := verifyRequest(req, r.server.cfg.Logs.Secret, bodyBytes); err != nil {
			r.logger.Warn("Signature verification failed", zap.Error(err))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	var logs []vercelLog

	// Try parsing as JSON array first
	if err := json.Unmarshal(bodyBytes, &logs); err != nil {
		// Try NDJSON format (newline-delimited JSON)
		decoder := json.NewDecoder(bytes.NewReader(bodyBytes))
		for {
			var log vercelLog
			if err := decoder.Decode(&log); err == io.EOF {
				break
			} else if err != nil {
				r.logger.Error("Failed to decode log data", zap.Error(err))
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}
			logs = append(logs, log)
		}
	}

	pLogs := convertVercelLogsToPdata(logs)

	obsCtx := r.obsrecv.StartLogsOp(req.Context())
	if err := r.consumer.ConsumeLogs(obsCtx, pLogs); err != nil {
		r.obsrecv.EndLogsOp(obsCtx, Type.String(), pLogs.LogRecordCount(), err)
		r.logger.Error("Failed to consume logs", zap.Error(err))

		// Check if it's a permanent error (should return 400)
		if consumererror.IsPermanent(err) {
			http.Error(w, "Bad request", http.StatusBadRequest)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	r.obsrecv.EndLogsOp(obsCtx, Type.String(), pLogs.LogRecordCount(), nil)
	w.WriteHeader(http.StatusOK)
}

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
