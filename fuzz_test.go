// Copyright The OpenTelemetry Authors

// SPDX-License-Identifier: Apache-2.0

package vercelreceiver

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"
)

// Helper function to create a test receiver with logs consumer
func newTestLogsReceiver(t *testing.T, cfg *Config) *logsReceiver {
	consumer := &consumertest.LogsSink{}
	params := receivertest.NewNopSettings(Type)
	r, err := newLogsReceiver(params, cfg, consumer)
	if err != nil {
		t.Fatalf("Failed to create logs receiver: %v", err)
	}
	return r
}

// Helper function to create a test receiver with traces consumer
func newTestTracesReceiver(t *testing.T, cfg *Config) *tracesReceiver {
	consumer := &consumertest.TracesSink{}
	params := receivertest.NewNopSettings(Type)
	r, err := newTracesReceiver(params, cfg, consumer)
	if err != nil {
		t.Fatalf("Failed to create traces receiver: %v", err)
	}
	return r
}

// Helper function to create a test receiver with metrics consumer
func newTestMetricsReceiver(t *testing.T, cfg *Config) *speedInsightsReceiver {
	consumer := &consumertest.MetricsSink{}
	params := receivertest.NewNopSettings(Type)
	r, err := newSpeedInsightsReceiver(params, cfg, consumer)
	if err != nil {
		t.Fatalf("Failed to create metrics receiver: %v", err)
	}
	return r
}

// Helper function to create a test receiver with web analytics consumer
func newTestWebAnalyticsReceiver(t *testing.T, cfg *Config) *webAnalyticsReceiver {
	consumer := &consumertest.LogsSink{}
	params := receivertest.NewNopSettings(Type)
	r, err := newWebAnalyticsReceiver(params, cfg, consumer)
	if err != nil {
		t.Fatalf("Failed to create web analytics receiver: %v", err)
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
		if err != nil {
			t.Skip()
		}

		secret := "test-secret"
		signature := generateSignature([]byte(secret), reqBody)
		req.Header.Add(xVercelSignatureHeader, signature)
		req.Header.Add("Content-Type", "application/json")

		if gZip {
			req.Header.Add("Content-Encoding", "gzip")
		}

		cfg := &Config{
			Logs: LogsConfig{
				Endpoint: "localhost:0",
				Secret:   secret,
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
		if err != nil {
			t.Skip()
		}

		secret := "test-secret"
		signature := generateSignature([]byte(secret), reqBody)
		req.Header.Add(xVercelSignatureHeader, signature)
		req.Header.Add("Content-Type", "application/json")

		if gZip {
			req.Header.Add("Content-Encoding", "gzip")
		}

		cfg := &Config{
			Traces: TracesConfig{
				Endpoint: "localhost:0",
				Secret:   secret,
			},
		}

		r := newTestTracesReceiver(t, cfg)
		rec := httptest.NewRecorder()
		r.handleTraces(rec, req)
	})
}

func FuzzHandleSpeedInsights(f *testing.F) {
	f.Fuzz(func(t *testing.T, reqBody []byte, gZip bool) {
		req, err := http.NewRequest(http.MethodPost, "http://example.com/speed-insights", bytes.NewReader(reqBody))
		if err != nil {
			t.Skip()
		}

		secret := "test-secret"
		signature := generateSignature([]byte(secret), reqBody)
		req.Header.Add(xVercelSignatureHeader, signature)
		req.Header.Add("Content-Type", "application/json")

		if gZip {
			req.Header.Add("Content-Encoding", "gzip")
		}

		cfg := &Config{
			SpeedInsights: SpeedInsightsConfig{
				Endpoint: "localhost:0",
				Secret:   secret,
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
		if err != nil {
			t.Skip()
		}

		secret := "test-secret"
		signature := generateSignature([]byte(secret), reqBody)
		req.Header.Add(xVercelSignatureHeader, signature)
		req.Header.Add("Content-Type", "application/json")

		if gZip {
			req.Header.Add("Content-Encoding", "gzip")
		}

		cfg := &Config{
			WebAnalytics: WebAnalyticsConfig{
				Endpoint: "localhost:0",
				Secret:   secret,
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
