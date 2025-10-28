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
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/receiverhelper"
	"go.uber.org/zap"
)

// webAnalyticsEvent represents a Vercel Web Analytics event
type webAnalyticsEvent struct {
	Schema               string `json:"schema"`
	EventType            string `json:"eventType"`
	EventName            string `json:"eventName,omitempty"`
	EventData            string `json:"eventData,omitempty"`
	Timestamp            int64  `json:"timestamp"`
	ProjectID            string `json:"projectId"`
	OwnerID              string `json:"ownerId"`
	DataSourceName       string `json:"dataSourceName"`
	SessionID            int64  `json:"sessionId"`
	DeviceID             int64  `json:"deviceId"`
	Origin               string `json:"origin"`
	Path                 string `json:"path"`
	Referrer             string `json:"referrer,omitempty"`
	QueryParams          string `json:"queryParams,omitempty"`
	Route                string `json:"route,omitempty"`
	Country              string `json:"country,omitempty"`
	Region               string `json:"region,omitempty"`
	City                 string `json:"city,omitempty"`
	OSName               string `json:"osName,omitempty"`
	OSVersion            string `json:"osVersion,omitempty"`
	ClientName           string `json:"clientName,omitempty"`
	ClientType           string `json:"clientType,omitempty"`
	ClientVersion        string `json:"clientVersion,omitempty"`
	DeviceType           string `json:"deviceType,omitempty"`
	DeviceBrand          string `json:"deviceBrand,omitempty"`
	DeviceModel          string `json:"deviceModel,omitempty"`
	BrowserEngine        string `json:"browserEngine,omitempty"`
	BrowserEngineVersion string `json:"browserEngineVersion,omitempty"`
	SDKVersion           string `json:"sdkVersion,omitempty"`
	SDKName              string `json:"sdkName,omitempty"`
	SDKVersionFull       string `json:"sdkVersionFull,omitempty"`
	VercelEnvironment    string `json:"vercelEnvironment,omitempty"`
	VercelURL            string `json:"vercelUrl,omitempty"`
	Flags                string `json:"flags,omitempty"`
	Deployment           string `json:"deployment,omitempty"`
}

// webAnalyticsReceiver handles Vercel Web Analytics drain data
type webAnalyticsReceiver struct {
	logger   *zap.Logger
	consumer consumer.Logs
	server   *httpServer
	wg       *sync.WaitGroup
	obsrecv  *receiverhelper.ObsReport
}

// newWebAnalyticsReceiver creates a new Web Analytics receiver
func newWebAnalyticsReceiver(params receiver.Settings, cfg *Config, consumer consumer.Logs) (*webAnalyticsReceiver, error) {
	obsrecv, err := receiverhelper.NewObsReport(receiverhelper.ObsReportSettings{
		ReceiverID:             params.ID,
		Transport:              "http",
		ReceiverCreateSettings: params,
	})
	if err != nil {
		return nil, err
	}

	r := &webAnalyticsReceiver{
		logger:   params.Logger,
		consumer: consumer,
		wg:       &sync.WaitGroup{},
		obsrecv:  obsrecv,
	}

	server := newHTTPServer(cfg, params.Logger)
	server.analyticsHandler = r.handleWebAnalytics
	r.server = server

	return r, nil
}

// Start starts the Web Analytics receiver
func (r *webAnalyticsReceiver) Start(ctx context.Context, host component.Host) error {
	return r.server.start()
}

// Shutdown stops the Web Analytics receiver
func (r *webAnalyticsReceiver) Shutdown(ctx context.Context) error {
	r.logger.Debug("Shutting down server")
	err := r.server.shutdown(ctx)
	if err != nil {
		return err
	}
	r.logger.Debug("Waiting for shutdown to complete.")
	r.wg.Wait()
	return nil
}

// handleWebAnalytics processes incoming Web Analytics drain requests
func (r *webAnalyticsReceiver) handleWebAnalytics(w http.ResponseWriter, req *http.Request) {
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

	obsCtx := r.obsrecv.StartLogsOp(req.Context())
	if err := r.consumer.ConsumeLogs(obsCtx, pLogs); err != nil {
		r.obsrecv.EndLogsOp(obsCtx, Type.String(), pLogs.LogRecordCount(), err)
		r.logger.Error("Failed to consume web analytics data", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	r.obsrecv.EndLogsOp(obsCtx, Type.String(), pLogs.LogRecordCount(), nil)
	w.WriteHeader(http.StatusOK)
}

// convertWebAnalyticsToPdata converts Web Analytics events to OpenTelemetry pdata.Logs
func convertWebAnalyticsToPdata(events []webAnalyticsEvent) plog.Logs {
	pLogs := plog.NewLogs()
	rl := pLogs.ResourceLogs().AppendEmpty()

	for _, event := range events {
		scopeLogs := rl.ScopeLogs().AppendEmpty()
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
