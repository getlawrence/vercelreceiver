//go:build integration

// Copyright The OpenTelemetry Authors

// SPDX-License-Identifier: Apache-2.0

package vercelreceiver

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"
)

const testSecret = "test-secret-12345"

// getAvailableLocalAddress returns an available local address with a free port
func getAvailableLocalAddress(t *testing.T) string {
	t.Helper()
	addr, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	defer addr.Close()
	return addr.Addr().String()
}

// Helper function to create a valid signature
func createSignature(secret []byte, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func TestLogsReceiverIntegration(t *testing.T) {
	testAddr := getAvailableLocalAddress(t)
	
	sink := &consumertest.LogsSink{}
	fact := NewFactory()

	recv, err := fact.CreateLogs(
		t.Context(),
		receivertest.NewNopSettings(Type),
		&Config{
			Logs: LogsConfig{
				Endpoint: testAddr,
				Secret:   testSecret,
			},
		},
		sink,
	)
	require.NoError(t, err)

	err = recv.Start(t.Context(), componenttest.NewNopHost())
	require.NoError(t, err)

	defer func() {
		require.NoError(t, recv.Shutdown(t.Context()))
	}()

	// Extract port from testAddr
	_, testPort, err := net.SplitHostPort(testAddr)
	require.NoError(t, err)

	// Wait for server to be ready
	require.Eventually(t, func() bool {
		resp, err := http.Get(fmt.Sprintf("http://localhost:%s/health", testPort))
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return true
		}
		return false
	}, 5*time.Second, 100*time.Millisecond)

	// Test payload - simple log array
	payload := []byte(`[{
		"id": "test123",
		"deploymentId": "dpl_test",
		"source": "build",
		"host": "test.vercel.app",
		"timestamp": 1573817187330,
		"level": "info",
		"message": "Test log message"
	}]`)

	// Test without secret first - should fail
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://localhost:%s/logs", testPort), bytes.NewBuffer(payload))
	require.NoError(t, err)

	req.Header.Add("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()

	// Add valid signature header
	signature := createSignature([]byte(testSecret), payload)
	req.Header.Set(xVercelSignatureHeader, signature)

	// Recreate request with signature
	req, err = http.NewRequest(http.MethodPost, fmt.Sprintf("http://localhost:%s/logs", testPort), bytes.NewBuffer(payload))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(xVercelSignatureHeader, signature)

	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Wait for logs to be consumed
	require.Eventually(t, func() bool {
		return sink.LogRecordCount() > 0
	}, 2*time.Second, 10*time.Millisecond)

	logs := sink.AllLogs()[0]
	require.Greater(t, logs.LogRecordCount(), 0)
}

func TestTracesReceiverIntegration(t *testing.T) {
	testAddr := getAvailableLocalAddress(t)
	
	sink := &consumertest.TracesSink{}
	fact := NewFactory()

	recv, err := fact.CreateTraces(
		t.Context(),
		receivertest.NewNopSettings(Type),
		&Config{
			Traces: TracesConfig{
				Endpoint: testAddr,
				Secret:   testSecret,
			},
		},
		sink,
	)
	require.NoError(t, err)

	err = recv.Start(t.Context(), componenttest.NewNopHost())
	require.NoError(t, err)

	defer func() {
		require.NoError(t, recv.Shutdown(t.Context()))
	}()

	// Extract port
	_, testPort, err := net.SplitHostPort(testAddr)
	require.NoError(t, err)

	// Wait for server to be ready
	require.Eventually(t, func() bool {
		resp, err := http.Get(fmt.Sprintf("http://localhost:%s/health", testPort))
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return true
		}
		return false
	}, 5*time.Second, 100*time.Millisecond)

	// Test payload - OTLP traces JSON format
	payload := []byte(`{
		"resourceSpans": [{
			"resource": {},
			"scopeSpans": [{
				"scope": {"name": "test"},
				"spans": [{
					"traceId": "7bba9f33312b3dbb8b2c2c62bb7abe2d",
					"spanId": "086e83747d0e381e",
					"name": "test_span",
					"kind": "SPAN_KIND_INTERNAL"
				}]
			}]
		}]
	}`)

	// Add valid signature header
	signature := createSignature([]byte(testSecret), payload)
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://localhost:%s/traces", testPort), bytes.NewBuffer(payload))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(xVercelSignatureHeader, signature)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Wait for traces to be consumed
	require.Eventually(t, func() bool {
		return len(sink.AllTraces()) > 0
	}, 2*time.Second, 10*time.Millisecond)

	traces := sink.AllTraces()[0]
	require.Greater(t, traces.SpanCount(), 0)
}

func TestSpeedInsightsReceiverIntegration(t *testing.T) {
	testAddr := getAvailableLocalAddress(t)
	
	sink := &consumertest.MetricsSink{}
	fact := NewFactory()

	recv, err := fact.CreateMetrics(
		t.Context(),
		receivertest.NewNopSettings(Type),
		&Config{
			SpeedInsights: SpeedInsightsConfig{
				Endpoint: testAddr,
				Secret:   testSecret,
			},
		},
		sink,
	)
	require.NoError(t, err)

	err = recv.Start(t.Context(), componenttest.NewNopHost())
	require.NoError(t, err)

	defer func() {
		require.NoError(t, recv.Shutdown(t.Context()))
	}()

	// Extract port
	_, testPort, err := net.SplitHostPort(testAddr)
	require.NoError(t, err)

	// Wait for server to be ready
	require.Eventually(t, func() bool {
		resp, err := http.Get(fmt.Sprintf("http://localhost:%s/health", testPort))
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return true
		}
		return false
	}, 5*time.Second, 100*time.Millisecond)

	// Test payload - speed insights format
	payload := []byte(`[{
		"schema": "vercel.speed_insights.v1",
		"timestamp": "2023-09-14T15:30:00.000Z",
		"metricType": "LCP",
		"value": 2.5
	}]`)

	// Add valid signature header
	signature := createSignature([]byte(testSecret), payload)
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://localhost:%s/speed-insights", testPort), bytes.NewBuffer(payload))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(xVercelSignatureHeader, signature)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Wait for metrics to be consumed
	require.Eventually(t, func() bool {
		return len(sink.AllMetrics()) > 0
	}, 2*time.Second, 10*time.Millisecond)

	metrics := sink.AllMetrics()[0]
	require.Greater(t, metrics.DataPointCount(), 0)
}

func TestWebAnalyticsReceiverIntegration(t *testing.T) {
	testAddr := getAvailableLocalAddress(t)
	
	sink := &consumertest.LogsSink{}
	fact := NewFactory()

	recv, err := fact.CreateLogs(
		t.Context(),
		receivertest.NewNopSettings(Type),
		&Config{
			WebAnalytics: WebAnalyticsConfig{
				Endpoint: testAddr,
				Secret:   testSecret,
			},
		},
		sink,
	)
	require.NoError(t, err)

	err = recv.Start(t.Context(), componenttest.NewNopHost())
	require.NoError(t, err)

	defer func() {
		require.NoError(t, recv.Shutdown(t.Context()))
	}()

	// Extract port
	_, testPort, err := net.SplitHostPort(testAddr)
	require.NoError(t, err)

	// Wait for server to be ready
	require.Eventually(t, func() bool {
		resp, err := http.Get(fmt.Sprintf("http://localhost:%s/health", testPort))
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return true
		}
		return false
	}, 5*time.Second, 100*time.Millisecond)

	// Test payload - web analytics format
	payload := []byte(`[{
		"path": "/test",
		"timestamp": 1573817187330,
		"hostname": "test.vercel.app"
	}]`)

	// Add valid signature header
	signature := createSignature([]byte(testSecret), payload)
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://localhost:%s/analytics", testPort), bytes.NewBuffer(payload))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(xVercelSignatureHeader, signature)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Wait for logs to be consumed
	require.Eventually(t, func() bool {
		return sink.LogRecordCount() > 0
	}, 2*time.Second, 10*time.Millisecond)

	logs := sink.AllLogs()[0]
	require.Greater(t, logs.LogRecordCount(), 0)
}

func TestNoSecretValidation(t *testing.T) {
	testAddr := getAvailableLocalAddress(t)
	
	sink := &consumertest.LogsSink{}
	fact := NewFactory()

	// Create receiver without secret - should accept requests without signature
	recv, err := fact.CreateLogs(
		t.Context(),
		receivertest.NewNopSettings(Type),
		&Config{
			Logs: LogsConfig{
				Endpoint: testAddr,
				Secret:   "", // No secret
			},
		},
		sink,
	)
	require.NoError(t, err)

	err = recv.Start(t.Context(), componenttest.NewNopHost())
	require.NoError(t, err)

	defer func() {
		require.NoError(t, recv.Shutdown(t.Context()))
	}()

	// Extract port
	_, testPort, err := net.SplitHostPort(testAddr)
	require.NoError(t, err)

	// Wait for server to be ready
	require.Eventually(t, func() bool {
		resp, err := http.Get(fmt.Sprintf("http://localhost:%s/health", testPort))
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return true
		}
		return false
	}, 5*time.Second, 100*time.Millisecond)

	payload := []byte(`[{
		"id": "test123",
		"message": "Test without secret"
	}]`)

	// Request without signature should succeed when no secret is configured
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://localhost:%s/logs", testPort), bytes.NewBuffer(payload))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}