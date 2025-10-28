package vercelreceiver

import (
	"context"
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

// tracesReceiver handles Vercel trace drain data
type tracesReceiver struct {
	logger   *zap.Logger
	consumer consumer.Traces
	server   *httpServer
	wg       *sync.WaitGroup
	obsrecv  *receiverhelper.ObsReport
}

// newTracesReceiver creates a new traces receiver
func newTracesReceiver(params receiver.Settings, cfg *Config, consumer consumer.Traces) (*tracesReceiver, error) {
	obsrecv, err := receiverhelper.NewObsReport(receiverhelper.ObsReportSettings{
		ReceiverID:             params.ID,
		Transport:              "http",
		ReceiverCreateSettings: params,
	})
	if err != nil {
		return nil, err
	}

	r := &tracesReceiver{
		logger:   params.Logger,
		consumer: consumer,
		wg:       &sync.WaitGroup{},
		obsrecv:  obsrecv,
	}

	server := newHTTPServer(cfg, params.Logger)
	server.tracesHandler = r.handleTraces
	r.server = server

	return r, nil
}

// Start starts the traces receiver
func (r *tracesReceiver) Start(ctx context.Context, host component.Host) error {
	return r.server.start()
}

// Shutdown stops the traces receiver
func (r *tracesReceiver) Shutdown(ctx context.Context) error {
	r.logger.Debug("Shutting down server")
	err := r.server.shutdown(ctx)
	if err != nil {
		return err
	}
	r.logger.Debug("Waiting for shutdown to complete.")
	r.wg.Wait()
	return nil
}

// handleTraces processes incoming trace drain requests
func (r *tracesReceiver) handleTraces(w http.ResponseWriter, req *http.Request) {
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
	if r.server.cfg.Traces.Secret != "" {
		if err := verifyRequest(req, r.server.cfg.Traces.Secret, bodyBytes); err != nil {
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

	obsCtx := r.obsrecv.StartTracesOp(req.Context())
	if err := r.consumer.ConsumeTraces(obsCtx, traces); err != nil {
		spans := traces.SpanCount()
		r.obsrecv.EndTracesOp(obsCtx, Type.String(), spans, err)
		r.logger.Error("Failed to consume traces", zap.Error(err))

		// Check if it's a permanent error (should return 400)
		if consumererror.IsPermanent(err) {
			http.Error(w, "Bad request", http.StatusBadRequest)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	spans := traces.SpanCount()
	r.obsrecv.EndTracesOp(obsCtx, Type.String(), spans, nil)
	w.WriteHeader(http.StatusOK)
}
