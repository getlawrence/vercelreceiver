package vercelreceiver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/receiverhelper"
	"go.uber.org/zap"
)

// speedInsight represents a Vercel Speed Insights metric entry
type speedInsight struct {
	Schema               string  `json:"schema"`
	Timestamp            string  `json:"timestamp"`
	ProjectID            string  `json:"projectId"`
	OwnerID              string  `json:"ownerId"`
	DeviceID             int64   `json:"deviceId"`
	MetricType           string  `json:"metricType"`
	Value                float64 `json:"value"`
	Origin               string  `json:"origin"`
	Path                 string  `json:"path"`
	Route                string  `json:"route,omitempty"`
	Country              string  `json:"country,omitempty"`
	Region               string  `json:"region,omitempty"`
	City                 string  `json:"city,omitempty"`
	OSName               string  `json:"osName,omitempty"`
	OSVersion            string  `json:"osVersion,omitempty"`
	ClientName           string  `json:"clientName,omitempty"`
	ClientType           string  `json:"clientType,omitempty"`
	ClientVersion        string  `json:"clientVersion,omitempty"`
	DeviceType           string  `json:"deviceType,omitempty"`
	DeviceBrand          string  `json:"deviceBrand,omitempty"`
	ConnectionSpeed      string  `json:"connectionSpeed,omitempty"`
	BrowserEngine        string  `json:"browserEngine,omitempty"`
	BrowserEngineVersion string  `json:"browserEngineVersion,omitempty"`
	ScriptVersion        string  `json:"scriptVersion,omitempty"`
	SDKVersion           string  `json:"sdkVersion,omitempty"`
	SDKName              string  `json:"sdkName,omitempty"`
	VercelEnvironment    string  `json:"vercelEnvironment,omitempty"`
	VercelURL            string  `json:"vercelUrl,omitempty"`
	DeploymentID         string  `json:"deploymentId,omitempty"`
	Attribution          string  `json:"attribution,omitempty"`
}

// speedInsightsReceiver handles Vercel Speed Insights drain data
type speedInsightsReceiver struct {
	logger   *zap.Logger
	consumer consumer.Metrics
	server   *httpServer
	wg       *sync.WaitGroup
	obsrecv  *receiverhelper.ObsReport
}

// newSpeedInsightsReceiver creates a new Speed Insights receiver
func newSpeedInsightsReceiver(params receiver.Settings, cfg *Config, consumer consumer.Metrics) (*speedInsightsReceiver, error) {
	obsrecv, err := receiverhelper.NewObsReport(receiverhelper.ObsReportSettings{
		ReceiverID:             params.ID,
		Transport:              "http",
		ReceiverCreateSettings: params,
	})
	if err != nil {
		return nil, err
	}

	r := &speedInsightsReceiver{
		logger:   params.Logger,
		consumer: consumer,
		wg:       &sync.WaitGroup{},
		obsrecv:  obsrecv,
	}

	server := newHTTPServer(cfg, params.Logger)
	server.speedInsightsHandler = r.handleSpeedInsights
	r.server = server

	return r, nil
}

// Start starts the Speed Insights receiver
func (r *speedInsightsReceiver) Start(ctx context.Context, host component.Host) error {
	return r.server.start()
}

// Shutdown stops the Speed Insights receiver
func (r *speedInsightsReceiver) Shutdown(ctx context.Context) error {
	r.logger.Debug("Shutting down server")
	err := r.server.shutdown(ctx)
	if err != nil {
		return err
	}
	r.logger.Debug("Waiting for shutdown to complete.")
	r.wg.Wait()
	return nil
}

// handleSpeedInsights processes incoming Speed Insights drain requests
func (r *speedInsightsReceiver) handleSpeedInsights(w http.ResponseWriter, req *http.Request) {
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
	if r.server.cfg.SpeedInsights.Secret != "" {
		if err := verifyRequest(req, r.server.cfg.SpeedInsights.Secret, bodyBytes); err != nil {
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

	obsCtx := r.obsrecv.StartMetricsOp(req.Context())
	if err := r.consumer.ConsumeMetrics(obsCtx, pMetrics); err != nil {
		dataPointCount := pMetrics.DataPointCount()
		r.obsrecv.EndMetricsOp(obsCtx, Type.String(), dataPointCount, err)
		r.logger.Error("Failed to consume metrics", zap.Error(err))

		// Check if it's a permanent error (should return 400)
		if consumererror.IsPermanent(err) {
			http.Error(w, "Bad request", http.StatusBadRequest)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	dataPointCount := pMetrics.DataPointCount()
	r.obsrecv.EndMetricsOp(obsCtx, Type.String(), dataPointCount, nil)
	w.WriteHeader(http.StatusOK)
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
