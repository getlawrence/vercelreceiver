// Copyright The OpenTelemetry Authors

// SPDX-License-Identifier: Apache-2.0

package vercelreceiver

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.uber.org/zap/zaptest"
)

func TestHandleTraces(t *testing.T) {
	testCases := []struct {
		name             string
		payload          string
		contentType      string
		hasSecret        bool
		consumerFailure  bool
		permanentFailure bool
		expectedStatus   int
		tracesExpected   bool
		isJSON           bool
	}{
		{
			name:           "missing signature with secret",
			payload:        `{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"vercel-function"}}]}}]}`,
			contentType:    "application/json",
			hasSecret:      true,
			expectedStatus: http.StatusUnauthorized,
			tracesExpected: false,
			isJSON:         true,
		},
		{
			name:           "invalid JSON payload",
			payload:        `{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name"`,
			contentType:    "application/json",
			hasSecret:      false,
			expectedStatus: http.StatusBadRequest,
			tracesExpected: false,
			isJSON:         true,
		},
		{
			name:           "valid JSON request",
			payload:        `{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"vercel-function"}}]},"scopeSpans":[{"scope":{"name":"vercel"},"spans":[{"traceId":"7bba9f33312b3dbb8b2c2c62bb7abe2d","spanId":"086e83747d0e381e","name":"GET /api/users","kind":"server","startTimeUnixNano":"1694723400000000000","endTimeUnixNano":"1694723400150000000"}]}]}]}`,
			contentType:    "application/json",
			hasSecret:      false,
			expectedStatus: http.StatusOK,
			tracesExpected: true,
			isJSON:         true,
		},
		{
			name:           "valid JSON request with signature",
			payload:        `{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"vercel-function"}}]},"scopeSpans":[{"scope":{"name":"vercel"},"spans":[{"traceId":"7bba9f33312b3dbb8b2c2c62bb7abe2d","spanId":"086e83747d0e381e","name":"GET /api/users","kind":"server","startTimeUnixNano":"1694723400000000000","endTimeUnixNano":"1694723400150000000"}]}]}]}`,
			contentType:    "application/json",
			hasSecret:      true,
			expectedStatus: http.StatusOK,
			tracesExpected: true,
			isJSON:         true,
		},
		{
			name:           "invalid protobuf payload",
			payload:        "this is not valid protobuf",
			contentType:    "application/x-protobuf",
			hasSecret:      false,
			expectedStatus: http.StatusBadRequest,
			tracesExpected: false,
		},
		{
			name:            "consumer fails",
			payload:         `{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"vercel-function"}}]}}]}`,
			contentType:     "application/json",
			hasSecret:       false,
			consumerFailure: true,
			expectedStatus:  http.StatusInternalServerError,
			tracesExpected:  false,
			isJSON:          true,
		},
		{
			name:             "consumer fails permanent error",
			payload:          `{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"vercel-function"}}]}}]}`,
			contentType:      "application/json",
			hasSecret:        false,
			consumerFailure:  true,
			permanentFailure: true,
			expectedStatus:   http.StatusBadRequest,
			tracesExpected:   false,
			isJSON:           true,
		},
		{
			name:           "wrong method",
			payload:        `{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"vercel-function"}}]}}]}`,
			contentType:    "application/json",
			hasSecret:      false,
			expectedStatus: http.StatusMethodNotAllowed,
			tracesExpected: false,
			isJSON:         true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var nextConsumer consumer.Traces
			var sink *consumertest.TracesSink

			if tc.consumerFailure {
				if tc.permanentFailure {
					nextConsumer = consumertest.NewErr(consumererror.NewPermanent(errors.New("permanent error")))
				} else {
					nextConsumer = consumertest.NewErr(errors.New("consumer failed"))
				}
			} else {
				sink = &consumertest.TracesSink{}
				nextConsumer = sink
			}

			cfg := &Config{
				Traces: TracesConfig{
					Endpoint: "localhost:0",
					Secret:   "",
				},
			}

			recv := newTestTracesReceiverForTest(t, cfg, nextConsumer)

			// Create request
			body := io.NopCloser(bytes.NewBufferString(tc.payload))
			req := httptest.NewRequest(http.MethodPost, "http://localhost/traces", body)

			req.Header.Set("Content-Type", tc.contentType)

			if tc.hasSecret {
				signature := createSignature([]byte(testSecret), []byte(tc.payload))
				req.Header.Set(xVercelSignatureHeader, signature)
			}

			if tc.expectedStatus == http.StatusMethodNotAllowed {
				req = httptest.NewRequest(http.MethodGet, "http://localhost/traces", body)
			}

			rec := httptest.NewRecorder()

			recv.handleTraces(rec, req)

			assert.Equal(t, tc.expectedStatus, rec.Code, "Status code mismatch")

			if !tc.consumerFailure && sink != nil && tc.tracesExpected && tc.isJSON {
				// For JSON, we can validate the traces were created
				require.Eventually(t, func() bool {
					return len(sink.AllTraces()) > 0
				}, 100*time.Millisecond, 10*time.Millisecond)
				traces := sink.AllTraces()[0]
				require.Greater(t, traces.SpanCount(), 0, "Expected spans but got none")
			}
		})
	}
}

func TestHandleTracesWithJSONFormat(t *testing.T) {
	t.Run("valid JSON trace payload", func(t *testing.T) {
		sink := &consumertest.TracesSink{}
		cfg := &Config{
			Traces: TracesConfig{
				Endpoint: "localhost:0",
				Secret:   "",
			},
		}

		recv := newTestTracesReceiverForTest(t, cfg, sink)

		// Sample JSON trace from testdata
		payload := `{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"vercel-function"}}]},"scopeSpans":[{"scope":{"name":"vercel"},"spans":[{"traceId":"7bba9f33312b3dbb8b2c2c62bb7abe2d","spanId":"086e83747d0e381e","name":"GET /api/users","kind":"server","startTimeUnixNano":"1694723400000000000","endTimeUnixNano":"1694723400150000000"}]}]}]}`

		body := io.NopCloser(bytes.NewBufferString(payload))
		req := httptest.NewRequest(http.MethodPost, "http://localhost/traces", body)
		req.Header.Set("Content-Type", "application/json")

		rec := httptest.NewRecorder()
		recv.handleTraces(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		require.Eventually(t, func() bool {
			return len(sink.AllTraces()) > 0
		}, 100*time.Millisecond, 10*time.Millisecond)

		traces := sink.AllTraces()[0]
		require.Greater(t, traces.SpanCount(), 0)
	})
}

func TestHandleTracesProtobufFormat(t *testing.T) {
	t.Run("invalid protobuf payload", func(t *testing.T) {
		sink := &consumertest.TracesSink{}
		cfg := &Config{
			Traces: TracesConfig{
				Endpoint: "localhost:0",
				Secret:   "",
			},
		}

		recv := newTestTracesReceiverForTest(t, cfg, sink)

		payload := "invalid protobuf data"
		body := io.NopCloser(bytes.NewBufferString(payload))
		req := httptest.NewRequest(http.MethodPost, "http://localhost/traces", body)
		req.Header.Set("Content-Type", "application/x-protobuf")

		rec := httptest.NewRecorder()
		recv.handleTraces(rec, req)

		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Equal(t, 0, len(sink.AllTraces()))
	})
}

func newTestTracesReceiverForTest(t *testing.T, cfg *Config, nextConsumer consumer.Traces) *tracesReceiver {
	set := receivertest.NewNopSettings(Type)
	set.Logger = zaptest.NewLogger(t)

	r, err := newTracesReceiver(set, cfg, nextConsumer)
	require.NoError(t, err)
	return r
}
