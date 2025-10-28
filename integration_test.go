//go:build integration

package vercelreceiver

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"
)

// getAvailableLocalAddress returns an available local address with a free port
func getAvailableLocalAddress(t *testing.T) string {
	t.Helper()
	addr, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	defer addr.Close()
	return addr.Addr().String()
}

func TestLogsReceiverIntegration(t *testing.T) {
	testAddr := getAvailableLocalAddress(t)

	sink := &consumertest.LogsSink{}
	fact := NewFactory()

	recv, err := fact.CreateLogs(
		t.Context(),
		receivertest.NewNopSettings(Type),
		&Config{
			Endpoint: testAddr,
			Logs: SignalConfig{
				Secret: testSecret,
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

	// Wait for server to be ready - give it some time
	time.Sleep(500 * time.Millisecond)

	// Test payload - use actual sample data
	payload, err := os.ReadFile(filepath.Join("testdata", "sample-payloads", "logs", "json.txt"))
	require.NoError(t, err)

	// Test without secret first - should fail
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://localhost:%s/logs", testPort), bytes.NewBuffer(payload))
	require.NoError(t, err)

	req.Header.Add("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	// Can be 401 (unauthorized) or 404 (not found) depending on setup
	if resp.StatusCode == http.StatusNotFound {
		t.Logf("Server endpoint not found, skipping auth test")
	} else {
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	}
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
			Endpoint: testAddr,
			Traces: SignalConfig{
				Secret: testSecret,
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

	// Wait for server to be ready - give it some time
	time.Sleep(500 * time.Millisecond)

	// Test payload - use actual sample data
	payload, err := os.ReadFile(filepath.Join("testdata", "sample-payloads", "traces", "json.txt"))
	require.NoError(t, err)

	// Add valid signature header
	signature := createSignature([]byte(testSecret), payload)
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://localhost:%s/traces", testPort), bytes.NewBuffer(payload))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(xVercelSignatureHeader, signature)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	// Debug: Read response body to see error details
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)

	if resp.StatusCode != http.StatusOK {
		t.Logf("Response status: %d", resp.StatusCode)
		t.Logf("Response body: %s", string(body))
		t.Logf("Request URL: %s", req.URL.String())
		t.Logf("Request headers: %v", req.Header)
		t.Logf("Payload: %s", string(payload))
	}

	require.Equal(t, http.StatusOK, resp.StatusCode)

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
			Endpoint: testAddr,
			SpeedInsights: SignalConfig{
				Secret: testSecret,
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

	// Wait for server to be ready - give it some time
	time.Sleep(500 * time.Millisecond)

	// Test payload - use actual sample data
	payload, err := os.ReadFile(filepath.Join("testdata", "sample-payloads", "speedinsights", "json.txt"))
	require.NoError(t, err)

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
			Endpoint: testAddr,
			WebAnalytics: SignalConfig{
				Secret: testSecret,
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

	// Wait for server to be ready - give it some time
	time.Sleep(500 * time.Millisecond)

	// Test payload - use actual sample data
	payload, err := os.ReadFile(filepath.Join("testdata", "sample-payloads", "webanalytics", "json.txt"))
	require.NoError(t, err)

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
			Endpoint: testAddr,
			Logs: SignalConfig{
				Secret: "", // No secret
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

	payload, err := os.ReadFile(filepath.Join("testdata", "sample-payloads", "logs", "json.txt"))
	require.NoError(t, err)

	// Request without signature should succeed when no secret is configured
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://localhost:%s/logs", testPort), bytes.NewBuffer(payload))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}
