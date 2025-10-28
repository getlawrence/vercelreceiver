package vercelreceiver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/receiverhelper"
	"go.uber.org/zap"
)

// vercelReceiver is a unified receiver that handles all Vercel data types
type vercelReceiver struct {
	logger *zap.Logger
	cfg    *Config

	// Consumers for each signal type
	logsConsumer    consumer.Logs
	tracesConsumer  consumer.Traces
	metricsConsumer consumer.Metrics

	// ObsReport for each signal type
	logsObsrecv    *receiverhelper.ObsReport
	tracesObsrecv  *receiverhelper.ObsReport
	metricsObsrecv *receiverhelper.ObsReport

	server *httpServer
	wg     *sync.WaitGroup
}

// newVercelReceiver creates a new unified Vercel receiver
func newVercelReceiver(
	params receiver.Settings,
	cfg *Config,
	logsConsumer consumer.Logs,
	tracesConsumer consumer.Traces,
	metricsConsumer consumer.Metrics,
) (*vercelReceiver, error) {
	r := &vercelReceiver{
		logger:          params.Logger,
		cfg:             cfg,
		logsConsumer:    logsConsumer,
		tracesConsumer:  tracesConsumer,
		metricsConsumer: metricsConsumer,
		wg:              &sync.WaitGroup{},
	}

	// Create ObsReport for each signal type if consumer is provided
	if logsConsumer != nil {
		obsrecv, err := receiverhelper.NewObsReport(receiverhelper.ObsReportSettings{
			ReceiverID:             params.ID,
			Transport:              "http",
			ReceiverCreateSettings: params,
		})
		if err != nil {
			return nil, err
		}
		r.logsObsrecv = obsrecv
	}

	if tracesConsumer != nil {
		obsrecv, err := receiverhelper.NewObsReport(receiverhelper.ObsReportSettings{
			ReceiverID:             params.ID,
			Transport:              "http",
			ReceiverCreateSettings: params,
		})
		if err != nil {
			return nil, err
		}
		r.tracesObsrecv = obsrecv
	}

	if metricsConsumer != nil {
		obsrecv, err := receiverhelper.NewObsReport(receiverhelper.ObsReportSettings{
			ReceiverID:             params.ID,
			Transport:              "http",
			ReceiverCreateSettings: params,
		})
		if err != nil {
			return nil, err
		}
		r.metricsObsrecv = obsrecv
	}

	// Create HTTP server with handlers
	server := newHTTPServer(cfg, params.Logger)
	if logsConsumer != nil {
		server.logsHandler = r.handleLogs
		server.analyticsHandler = r.handleWebAnalytics
	}
	if tracesConsumer != nil {
		server.tracesHandler = r.handleTraces
	}
	if metricsConsumer != nil {
		server.speedInsightsHandler = r.handleSpeedInsights
	}
	r.server = server

	return r, nil
}

// Start starts the receiver
func (r *vercelReceiver) Start(ctx context.Context, host component.Host) error {
	return r.server.start()
}

// Shutdown stops the receiver
func (r *vercelReceiver) Shutdown(ctx context.Context) error {
	r.logger.Debug("Shutting down receiver")
	err := r.server.shutdown(ctx)
	if err != nil {
		return err
	}
	r.logger.Debug("Waiting for shutdown to complete")
	r.wg.Wait()
	return nil
}

// handleLogs processes incoming log drain requests
func (r *vercelReceiver) handleLogs(w http.ResponseWriter, req *http.Request) {
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

	// Verify signature if secret is configured
	secret := r.cfg.GetLogsSecret()
	if secret != "" {
		if err := verifyRequest(req, secret, bodyBytes); err != nil {
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

	obsCtx := r.logsObsrecv.StartLogsOp(req.Context())
	if err := r.logsConsumer.ConsumeLogs(obsCtx, pLogs); err != nil {
		r.logsObsrecv.EndLogsOp(obsCtx, Type.String(), pLogs.LogRecordCount(), err)
		r.logger.Error("Failed to consume logs", zap.Error(err))

		if consumererror.IsPermanent(err) {
			http.Error(w, "Bad request", http.StatusBadRequest)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	r.logsObsrecv.EndLogsOp(obsCtx, Type.String(), pLogs.LogRecordCount(), nil)
	w.WriteHeader(http.StatusOK)
}

// handleTraces processes incoming trace drain requests
func (r *vercelReceiver) handleTraces(w http.ResponseWriter, req *http.Request) {
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

	// Verify signature if secret is configured
	secret := r.cfg.GetTracesSecret()
	if secret != "" {
		if err := verifyRequest(req, secret, bodyBytes); err != nil {
			r.logger.Warn("Signature verification failed", zap.Error(err))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// Determine format from Content-Type header
	contentType := req.Header.Get("Content-Type")

	var traces ptrace.Traces

	if contentType == "application/x-protobuf" || contentType == "application/octet-stream" {
		// Handle Protobuf format
		unmarshaler := ptrace.ProtoUnmarshaler{}
		traces, err = unmarshaler.UnmarshalTraces(bodyBytes)
		if err != nil {
			r.logger.Error("Failed to unmarshal protobuf traces", zap.Error(err))
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
	} else {
		// Handle JSON format (default)
		unmarshaler := ptrace.JSONUnmarshaler{}
		traces, err = unmarshaler.UnmarshalTraces(bodyBytes)
		if err != nil {
			r.logger.Error("Failed to unmarshal JSON traces", zap.Error(err))
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
	}

	obsCtx := r.tracesObsrecv.StartTracesOp(req.Context())
	if err := r.tracesConsumer.ConsumeTraces(obsCtx, traces); err != nil {
		spans := traces.SpanCount()
		r.tracesObsrecv.EndTracesOp(obsCtx, Type.String(), spans, err)
		r.logger.Error("Failed to consume traces", zap.Error(err))

		if consumererror.IsPermanent(err) {
			http.Error(w, "Bad request", http.StatusBadRequest)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	spans := traces.SpanCount()
	r.tracesObsrecv.EndTracesOp(obsCtx, Type.String(), spans, nil)
	w.WriteHeader(http.StatusOK)
}

// handleSpeedInsights processes incoming Speed Insights drain requests
func (r *vercelReceiver) handleSpeedInsights(w http.ResponseWriter, req *http.Request) {
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

	// Verify signature if secret is configured
	secret := r.cfg.GetSpeedInsightsSecret()
	if secret != "" {
		if err := verifyRequest(req, secret, bodyBytes); err != nil {
			r.logger.Warn("Signature verification failed", zap.Error(err))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	var insights []speedInsight

	// Try parsing as JSON array first
	if err := json.Unmarshal(bodyBytes, &insights); err != nil {
		// Try NDJSON format (newline-delimited JSON)
		decoder := json.NewDecoder(bytes.NewReader(bodyBytes))
		for {
			var insight speedInsight
			if err := decoder.Decode(&insight); err == io.EOF {
				break
			} else if err != nil {
				r.logger.Error("Failed to decode speed insights data", zap.Error(err))
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}
			insights = append(insights, insight)
		}
	}

	pMetrics := convertSpeedInsightsToPdata(insights)

	obsCtx := r.metricsObsrecv.StartMetricsOp(req.Context())
	if err := r.metricsConsumer.ConsumeMetrics(obsCtx, pMetrics); err != nil {
		dataPointCount := pMetrics.DataPointCount()
		r.metricsObsrecv.EndMetricsOp(obsCtx, Type.String(), dataPointCount, err)
		r.logger.Error("Failed to consume metrics", zap.Error(err))

		if consumererror.IsPermanent(err) {
			http.Error(w, "Bad request", http.StatusBadRequest)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	dataPointCount := pMetrics.DataPointCount()
	r.metricsObsrecv.EndMetricsOp(obsCtx, Type.String(), dataPointCount, nil)
	w.WriteHeader(http.StatusOK)
}

// handleWebAnalytics processes incoming Web Analytics drain requests
func (r *vercelReceiver) handleWebAnalytics(w http.ResponseWriter, req *http.Request) {
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

	// Verify signature if secret is configured
	secret := r.cfg.GetWebAnalyticsSecret()
	if secret != "" {
		if err := verifyRequest(req, secret, bodyBytes); err != nil {
			r.logger.Warn("Signature verification failed", zap.Error(err))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	var events []webAnalyticsEvent

	// Try parsing as JSON array first
	if err := json.Unmarshal(bodyBytes, &events); err != nil {
		// Try NDJSON format (newline-delimited JSON)
		decoder := json.NewDecoder(bytes.NewReader(bodyBytes))
		for {
			var event webAnalyticsEvent
			if err := decoder.Decode(&event); err == io.EOF {
				break
			} else if err != nil {
				r.logger.Error("Failed to decode web analytics data", zap.Error(err))
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}
			events = append(events, event)
		}
	}

	pLogs := convertWebAnalyticsToPdata(events)

	obsCtx := r.logsObsrecv.StartLogsOp(req.Context())
	if err := r.logsConsumer.ConsumeLogs(obsCtx, pLogs); err != nil {
		r.logsObsrecv.EndLogsOp(obsCtx, Type.String(), pLogs.LogRecordCount(), err)
		r.logger.Error("Failed to consume web analytics data", zap.Error(err))

		if consumererror.IsPermanent(err) {
			http.Error(w, "Bad request", http.StatusBadRequest)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	r.logsObsrecv.EndLogsOp(obsCtx, Type.String(), pLogs.LogRecordCount(), nil)
	w.WriteHeader(http.StatusOK)
}
