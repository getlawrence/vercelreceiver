package vercelreceiver

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"
)

// Helper function to create a test receiver with logs consumer
func newTestLogsReceiver(t *testing.T, cfg *Config) *vercelReceiver {
	logsConsumer := &consumertest.LogsSink{}
	params := receivertest.NewNopSettings(Type)
	r := newVercelReceiver(params, cfg)
	if err := r.RegisterLogsConsumer(logsConsumer, params); err != nil {
		t.Fatalf("Failed to register logs consumer: %v", err)
	}
	return r
}

// Helper function to create a test receiver with traces consumer
func newTestTracesReceiver(cfg *Config) *vercelReceiver {
	tracesConsumer := &consumertest.TracesSink{}
	params := receivertest.NewNopSettings(Type)
	r := newVercelReceiver(params, cfg)
	r.tracesConsumer = tracesConsumer
	r.server.tracesHandler = r.handleTraces
	return r
}

// Helper function to create a test receiver with metrics consumer
func newTestMetricsReceiver(t *testing.T, cfg *Config) *vercelReceiver {
	metricsConsumer := &consumertest.MetricsSink{}
	params := receivertest.NewNopSettings(Type)
	r := newVercelReceiver(params, cfg)
	if err := r.RegisterMetricsConsumer(metricsConsumer, params); err != nil {
		t.Fatalf("Failed to register metrics consumer: %v", err)
	}
	return r
}

// Helper function to create a test receiver with web analytics consumer
func newTestWebAnalyticsReceiver(t *testing.T, cfg *Config) *vercelReceiver {
	logsConsumer := &consumertest.LogsSink{}
	params := receivertest.NewNopSettings(Type)
	r := newVercelReceiver(params, cfg)
	if err := r.RegisterLogsConsumer(logsConsumer, params); err != nil {
		t.Fatalf("Failed to register logs consumer: %v", err)
	}
	return r
}

// Helper function to generate a valid signature for the given secret and body
func generateSignature(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func FuzzHandleLogs(f *testing.F) {
	f.Fuzz(func(t *testing.T, reqBody []byte, gZip bool) {
		req, err := http.NewRequest(http.MethodPost, "http://example.com/logs", bytes.NewReader(reqBody))
		require.NoError(t, err)

		secret := "test-secret"
		signature := generateSignature([]byte(secret), reqBody)
		req.Header.Add(xVercelSignatureHeader, signature)
		req.Header.Add("Content-Type", "application/json")

		if gZip {
			req.Header.Add("Content-Encoding", "gzip")
		}

		cfg := &Config{
			Endpoint: "localhost:0",
			Logs: SignalConfig{
				Secret: secret,
			},
		}

		r := newTestLogsReceiver(t, cfg)
		rec := httptest.NewRecorder()
		r.handleLogs(rec, req)
	})
}

func FuzzHandleTraces(f *testing.F) {
	f.Fuzz(func(t *testing.T, reqBody []byte, gZip bool) {
		req, err := http.NewRequest(http.MethodPost, "http://example.com/traces", bytes.NewReader(reqBody))
		require.NoError(t, err)
		secret := "test-secret"
		signature := generateSignature([]byte(secret), reqBody)
		req.Header.Add(xVercelSignatureHeader, signature)
		req.Header.Add("Content-Type", "application/json")

		if gZip {
			req.Header.Add("Content-Encoding", "gzip")
		}

		cfg := &Config{
			Endpoint: "localhost:0",
			Traces: SignalConfig{
				Secret: secret,
			},
		}

		r := newTestTracesReceiver(cfg)
		rec := httptest.NewRecorder()
		r.handleTraces(rec, req)
	})
}

func FuzzHandleSpeedInsights(f *testing.F) {
	f.Fuzz(func(t *testing.T, reqBody []byte, gZip bool) {
		req, err := http.NewRequest(http.MethodPost, "http://example.com/speed-insights", bytes.NewReader(reqBody))
		require.NoError(t, err)

		secret := "test-secret"
		signature := generateSignature([]byte(secret), reqBody)
		req.Header.Add(xVercelSignatureHeader, signature)
		req.Header.Add("Content-Type", "application/json")

		if gZip {
			req.Header.Add("Content-Encoding", "gzip")
		}

		cfg := &Config{
			Endpoint: "localhost:0",
			SpeedInsights: SignalConfig{
				Secret: secret,
			},
		}

		r := newTestMetricsReceiver(t, cfg)
		rec := httptest.NewRecorder()
		r.handleSpeedInsights(rec, req)
	})
}

func FuzzHandleWebAnalytics(f *testing.F) {
	f.Fuzz(func(t *testing.T, reqBody []byte, gZip bool) {
		req, err := http.NewRequest(http.MethodPost, "http://example.com/analytics", bytes.NewReader(reqBody))
		require.NoError(t, err)

		secret := "test-secret"
		signature := generateSignature([]byte(secret), reqBody)
		req.Header.Add(xVercelSignatureHeader, signature)
		req.Header.Add("Content-Type", "application/json")

		if gZip {
			req.Header.Add("Content-Encoding", "gzip")
		}

		cfg := &Config{
			Endpoint: "localhost:0",
			WebAnalytics: SignalConfig{
				Secret: secret,
			},
		}

		r := newTestWebAnalyticsReceiver(t, cfg)
		rec := httptest.NewRecorder()
		r.handleWebAnalytics(rec, req)
	})
}

// Fuzz test for signature verification
func FuzzVerifySignature(f *testing.F) {
	f.Fuzz(func(t *testing.T, secret []byte, body []byte, signature string) {
		// Test signature verification with various inputs
		verifySignature(secret, body, signature)
	})
}

// Fuzz test for endpoint validation
func FuzzValidateEndpoint(f *testing.F) {
	f.Fuzz(func(t *testing.T, endpoint string) {
		// Test endpoint validation with various inputs
		_ = validateEndpoint(endpoint) // intentionally ignore error for fuzz testing
	})
}
