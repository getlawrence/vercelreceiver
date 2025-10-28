package vercelreceiver

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.uber.org/zap/zaptest"
)

const testSecret = "test-secret-12345"

// Helper function to create a valid signature
func createSignature(secret []byte, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func TestConvertVercelLogsToPdata(t *testing.T) {
	testCases := []struct {
		name         string
		logs         []vercelLog
		expectedFunc func(*testing.T) plog.Logs
	}{
		{
			name: "basic log entry",
			logs: []vercelLog{
				{
					ID:           "1573817187330377061717300000",
					DeploymentID: "dpl_233NRGRjVZX1caZrXWtz5g1TAksD",
					Source:       "build",
					Host:         "my-app.vercel.app",
					Timestamp:    1573817187330,
					ProjectID:    "gdufoJxB6b9b1fEqr1jUtFkyavUU",
					Level:        "info",
					Message:      "Build completed successfully",
					BuildID:      "bld_cotnkcr76",
					Type:         "stdout",
					ProjectName:  "my-app",
				},
			},
			expectedFunc: func(t *testing.T) plog.Logs {
				expected := plog.NewLogs()
				rl := expected.ResourceLogs().AppendEmpty()
				sl := rl.ScopeLogs().AppendEmpty()

				lr := sl.LogRecords().AppendEmpty()
				lr.SetTimestamp(pcommon.NewTimestampFromTime(time.Unix(0, 1573817187330*int64(time.Millisecond))))
				lr.SetSeverityNumber(plog.SeverityNumberInfo)
				lr.SetSeverityText("INFO")

				body := pcommon.NewValueStr("Build completed successfully")
				body.CopyTo(lr.Body())

				attrs := lr.Attributes()
				attrs.PutStr("log.id", "1573817187330377061717300000")
				attrs.PutStr("deployment.id", "dpl_233NRGRjVZX1caZrXWtz5g1TAksD")
				attrs.PutStr("source", "build")
				attrs.PutStr("host", "my-app.vercel.app")
				attrs.PutStr("project.id", "gdufoJxB6b9b1fEqr1jUtFkyavUU")
				attrs.PutStr("build.id", "bld_cotnkcr76")
				attrs.PutStr("type", "stdout")
				attrs.PutStr("project.name", "my-app")

				return expected
			},
		},
		{
			name: "log with severity levels",
			logs: []vercelLog{
				{Level: "error", Message: "Error occurred", Timestamp: 1573817187330},
				{Level: "warning", Message: "Warning message", Timestamp: 1573817187340},
				{Level: "fatal", Message: "Fatal error", Timestamp: 1573817187350},
			},
			expectedFunc: func(t *testing.T) plog.Logs {
				expected := plog.NewLogs()
				rl := expected.ResourceLogs().AppendEmpty()

				// Each log gets its own scope in the implementation
				// Error log
				sl1 := rl.ScopeLogs().AppendEmpty()
				lr1 := sl1.LogRecords().AppendEmpty()
				lr1.SetTimestamp(pcommon.NewTimestampFromTime(time.Unix(0, 1573817187330*int64(time.Millisecond))))
				lr1.SetSeverityNumber(plog.SeverityNumberError)
				lr1.SetSeverityText("ERROR")
				pcommon.NewValueStr("Error occurred").CopyTo(lr1.Body())

				// Warning log
				sl2 := rl.ScopeLogs().AppendEmpty()
				lr2 := sl2.LogRecords().AppendEmpty()
				lr2.SetTimestamp(pcommon.NewTimestampFromTime(time.Unix(0, 1573817187340*int64(time.Millisecond))))
				lr2.SetSeverityNumber(plog.SeverityNumberWarn)
				lr2.SetSeverityText("WARN")
				pcommon.NewValueStr("Warning message").CopyTo(lr2.Body())

				// Fatal log
				sl3 := rl.ScopeLogs().AppendEmpty()
				lr3 := sl3.LogRecords().AppendEmpty()
				lr3.SetTimestamp(pcommon.NewTimestampFromTime(time.Unix(0, 1573817187350*int64(time.Millisecond))))
				lr3.SetSeverityNumber(plog.SeverityNumberFatal)
				lr3.SetSeverityText("FATAL")
				pcommon.NewValueStr("Fatal error").CopyTo(lr3.Body())

				return expected
			},
		},
		{
			name: "log with trace and span IDs",
			logs: []vercelLog{
				{
					Level:     "info",
					Message:   "API call",
					Timestamp: 1573817187330,
					TraceID:   "1b02cd14bb8642fd092bc23f54c7ffcd",
					SpanID:    "f24e8631bd11faa7",
				},
				{
					Level:      "info",
					Message:    "Another API call",
					Timestamp:  1573817187340,
					TraceIDAlt: "2c13de25cc9753ge1a03cd34g65d8ggde",
					SpanIDAlt:  "e35f9742ce22fbb8",
				},
			},
			expectedFunc: func(t *testing.T) plog.Logs {
				expected := plog.NewLogs()
				rl := expected.ResourceLogs().AppendEmpty()

				// Each log gets its own scope
				sl1 := rl.ScopeLogs().AppendEmpty()
				lr1 := sl1.LogRecords().AppendEmpty()
				lr1.SetTimestamp(pcommon.NewTimestampFromTime(time.Unix(0, 1573817187330*int64(time.Millisecond))))
				lr1.SetSeverityNumber(plog.SeverityNumberInfo)
				lr1.SetSeverityText("INFO")
				pcommon.NewValueStr("API call").CopyTo(lr1.Body())
				traceID := parseTraceID("1b02cd14bb8642fd092bc23f54c7ffcd")
				spanID := parseSpanID("f24e8631bd11faa7")
				lr1.SetTraceID(traceID)
				lr1.SetSpanID(spanID)

				sl2 := rl.ScopeLogs().AppendEmpty()
				lr2 := sl2.LogRecords().AppendEmpty()
				lr2.SetTimestamp(pcommon.NewTimestampFromTime(time.Unix(0, 1573817187340*int64(time.Millisecond))))
				lr2.SetSeverityNumber(plog.SeverityNumberInfo)
				lr2.SetSeverityText("INFO")
				pcommon.NewValueStr("Another API call").CopyTo(lr2.Body())
				traceID2 := parseTraceID("2c13de25cc9753ge1a03cd34g65d8ggde")
				spanID2 := parseSpanID("e35f9742ce22fbb8")
				lr2.SetTraceID(traceID2)
				lr2.SetSpanID(spanID2)

				return expected
			},
		},
		{
			name: "log with proxy data",
			logs: []vercelLog{
				{
					Level:     "info",
					Message:   "Request processed",
					Timestamp: 1573817187330,
					Proxy: &vercelProxy{
						Timestamp:        1573817250172,
						Method:           "GET",
						Host:             "my-app.vercel.app",
						Path:             "/api/users?page=1",
						UserAgent:        []string{"Mozilla/5.0"},
						Referer:          "https://my-app.vercel.app",
						Region:           "sfo1",
						StatusCode:       200,
						ClientIP:         "120.75.16.101",
						Scheme:           "https",
						ResponseByteSize: 1234,
						CacheID:          "cache123",
						PathType:         "serverless",
						PathTypeVariant:  "lambda",
						VercelID:         "vercel-id-123",
						VercelCache:      "MISS",
						LambdaRegion:     "sfo1",
						WAFAction:        "allow",
						WAFRuleID:        "rule-123",
					},
				},
			},
			expectedFunc: func(t *testing.T) plog.Logs {
				expected := plog.NewLogs()
				rl := expected.ResourceLogs().AppendEmpty()
				sl := rl.ScopeLogs().AppendEmpty()

				lr := sl.LogRecords().AppendEmpty()
				lr.SetTimestamp(pcommon.NewTimestampFromTime(time.Unix(0, 1573817187330*int64(time.Millisecond))))
				lr.SetSeverityNumber(plog.SeverityNumberInfo)
				lr.SetSeverityText("INFO")
				pcommon.NewValueStr("Request processed").CopyTo(lr.Body())

				attrs := lr.Attributes()
				attrs.PutInt("proxy.timestamp", 1573817250172)
				attrs.PutStr("proxy.method", "GET")
				attrs.PutStr("proxy.host", "my-app.vercel.app")
				attrs.PutStr("proxy.path", "/api/users?page=1")
				attrs.PutStr("proxy.user.agent", "Mozilla/5.0")
				attrs.PutStr("proxy.referer", "https://my-app.vercel.app")
				attrs.PutStr("proxy.region", "sfo1")
				attrs.PutInt("proxy.status.code", 200)
				attrs.PutStr("proxy.client.ip", "120.75.16.101")
				attrs.PutStr("proxy.scheme", "https")
				attrs.PutInt("proxy.response.byte.size", 1234)
				attrs.PutStr("proxy.cache.id", "cache123")
				attrs.PutStr("proxy.path.type", "serverless")
				attrs.PutStr("proxy.path.type.variant", "lambda")
				attrs.PutStr("proxy.vercel.id", "vercel-id-123")
				attrs.PutStr("proxy.vercel.cache", "MISS")
				attrs.PutStr("proxy.lambda.region", "sfo1")
				attrs.PutStr("proxy.waf.action", "allow")
				attrs.PutStr("proxy.waf.rule.id", "rule-123")

				return expected
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			expected := tc.expectedFunc(t)
			actual := convertVercelLogsToPdata(tc.logs)

			// Compare log record count
			require.Equal(t, expected.LogRecordCount(), actual.LogRecordCount(), "Log record count mismatch")

			// Compare each log record
			expectedRL := expected.ResourceLogs().At(0)
			actualRL := actual.ResourceLogs().At(0)

			require.Equal(t, expectedRL.ScopeLogs().Len(), actualRL.ScopeLogs().Len())

			for i := 0; i < expectedRL.ScopeLogs().Len(); i++ {
				expectedSL := expectedRL.ScopeLogs().At(i)
				actualSL := actualRL.ScopeLogs().At(i)

				require.Equal(t, expectedSL.LogRecords().Len(), actualSL.LogRecords().Len())

				for j := 0; j < expectedSL.LogRecords().Len(); j++ {
					expectedLR := expectedSL.LogRecords().At(j)
					actualLR := actualSL.LogRecords().At(j)

					// Compare timestamps (allow small differences)
					assert.Equal(t, expectedLR.Timestamp().AsTime().Unix(), actualLR.Timestamp().AsTime().Unix())

					// Compare severity
					assert.Equal(t, expectedLR.SeverityNumber(), actualLR.SeverityNumber())
					assert.Equal(t, expectedLR.SeverityText(), actualLR.SeverityText())

					// Compare trace and span IDs
					assert.Equal(t, expectedLR.TraceID(), actualLR.TraceID())
					assert.Equal(t, expectedLR.SpanID(), actualLR.SpanID())

					// Compare body
					assert.Equal(t, expectedLR.Body().AsString(), actualLR.Body().AsString())

					// Compare attributes
					expectedAttrs := expectedLR.Attributes()
					actualAttrs := actualLR.Attributes()

					expectedAttrs.Range(func(k string, v pcommon.Value) bool {
						actualVal, exists := actualAttrs.Get(k)
						require.True(t, exists, "Missing attribute: %s", k)
						assert.Equal(t, v.AsString(), actualVal.AsString(), "Attribute value mismatch: %s", k)
						return true
					})
				}
			}
		})
	}
}

func TestHandleLogs(t *testing.T) {
	testCases := []struct {
		name               string
		payload            string
		hasSecret          bool
		secret             string
		consumerFailure    bool
		permanentFailure   bool
		expectedStatusCode int
		logExpected        bool
		addSignature       bool // whether to actually add signature to request
	}{
		{
			name:               "missing signature",
			payload:            `[{"id":"1","timestamp":1573817187330,"level":"info","message":"test"}]`,
			hasSecret:          true,
			secret:             testSecret,
			expectedStatusCode: http.StatusUnauthorized,
			logExpected:        false,
			addSignature:       false,
		},
		{
			name:               "invalid signature",
			payload:            `[{"id":"1","timestamp":1573817187330,"level":"info","message":"test"}]`,
			hasSecret:          true,
			secret:             testSecret,
			expectedStatusCode: http.StatusUnauthorized,
			logExpected:        false,
			addSignature:       true, // but add wrong signature
		},
		{
			name:               "invalid JSON payload",
			payload:            `[{"id":"1","timestamp":1573817187330,"level":"info","message":"test"`,
			hasSecret:          false,
			expectedStatusCode: http.StatusBadRequest,
			logExpected:        false,
		},
		{
			name:               "valid request",
			payload:            `[{"id":"1","timestamp":1573817187330,"level":"info","message":"test"}]`,
			hasSecret:          false,
			expectedStatusCode: http.StatusOK,
			logExpected:        true,
		},
		{
			name:               "valid request with signature",
			payload:            `[{"id":"1","timestamp":1573817187330,"level":"info","message":"test"}]`,
			hasSecret:          true,
			secret:             testSecret,
			expectedStatusCode: http.StatusOK,
			logExpected:        true,
			addSignature:       true,
		},
		{
			name:               "consumer fails",
			payload:            `[{"id":"1","timestamp":1573817187330,"level":"info","message":"test"}]`,
			hasSecret:          false,
			consumerFailure:    true,
			expectedStatusCode: http.StatusInternalServerError,
			logExpected:        false,
		},
		{
			name:               "consumer fails permanent error",
			payload:            `[{"id":"1","timestamp":1573817187330,"level":"info","message":"test"}]`,
			hasSecret:          false,
			consumerFailure:    true,
			permanentFailure:   true,
			expectedStatusCode: http.StatusBadRequest,
			logExpected:        false,
		},
		{
			name:               "NDJSON format",
			payload:            `{"id":"1","timestamp":1573817187330,"level":"info","message":"test"}` + "\n" + `{"id":"2","timestamp":1573817187340,"level":"warn","message":"warning"}`,
			hasSecret:          false,
			expectedStatusCode: http.StatusOK,
			logExpected:        true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var nextConsumer consumer.Logs
			var sink *consumertest.LogsSink

			if tc.consumerFailure {
				if tc.permanentFailure {
					nextConsumer = consumertest.NewErr(consumererror.NewPermanent(errors.New("permanent error")))
				} else {
					nextConsumer = consumertest.NewErr(errors.New("consumer failed"))
				}
			} else {
				sink = &consumertest.LogsSink{}
				nextConsumer = sink
			}

			cfg := &Config{
				Endpoint: "localhost:0",
				Logs: SignalConfig{
					Secret: tc.secret,
				},
			}

			recv := newTestLogsReceiverForTest(t, cfg, nextConsumer)

			// Create request
			body := io.NopCloser(bytes.NewBufferString(tc.payload))
			req := httptest.NewRequest(http.MethodPost, "http://localhost/logs", body)

			if tc.addSignature && tc.secret != "" {
				var signature string
				if tc.name == "invalid signature" {
					// For invalid signature test, use wrong secret
					signature = createSignature([]byte("wrong-secret"), []byte(tc.payload))
				} else {
					signature = createSignature([]byte(tc.secret), []byte(tc.payload))
				}
				req.Header.Set(xVercelSignatureHeader, signature)
			}

			rec := httptest.NewRecorder()

			recv.handleLogs(rec, req)

			assert.Equal(t, tc.expectedStatusCode, rec.Code, "Status code mismatch")

			if !tc.consumerFailure && sink != nil {
				if tc.logExpected {
					// Wait a bit for async processing if needed
					time.Sleep(10 * time.Millisecond)
					assert.Greater(t, sink.LogRecordCount(), 0, "Expected log records but got none")
				} else {
					assert.Equal(t, 0, sink.LogRecordCount(), "Did not expect log records but got some")
				}
			}
		})
	}
}

func newTestLogsReceiverForTest(t *testing.T, cfg *Config, nextConsumer consumer.Logs) *vercelReceiver {
	set := receivertest.NewNopSettings(Type)
	set.Logger = zaptest.NewLogger(t)

	r := newVercelReceiver(set, cfg)
	err := r.RegisterLogsConsumer(nextConsumer, set)
	require.NoError(t, err)
	return r
}
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
		addSignature     bool // whether to actually add signature to request
	}{
		{
			name:           "missing signature with secret",
			payload:        `{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"vercel-function"}}]}}]}`,
			contentType:    "application/json",
			hasSecret:      true,
			expectedStatus: http.StatusUnauthorized,
			tracesExpected: false,
			isJSON:         true,
			addSignature:   false, // Don't add signature even though hasSecret is true
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
			payload:        `{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"vercel-function"}}]},"scopeSpans":[{"scope":{"name":"vercel"},"spans":[{"traceId":"7bba9f33312b3dbb8b2c2c62bb7abe2d","spanId":"086e83747d0e381e","name":"GET /api/users","kind":2,"startTimeUnixNano":"1694723400000000000","endTimeUnixNano":"1694723400150000000"}]}]}]}`,
			contentType:    "application/json",
			hasSecret:      false,
			expectedStatus: http.StatusOK,
			tracesExpected: true,
			isJSON:         true,
		},
		{
			name:           "valid JSON request with signature",
			payload:        `{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"vercel-function"}}]},"scopeSpans":[{"scope":{"name":"vercel"},"spans":[{"traceId":"7bba9f33312b3dbb8b2c2c62bb7abe2d","spanId":"086e83747d0e381e","name":"GET /api/users","kind":2,"startTimeUnixNano":"1694723400000000000","endTimeUnixNano":"1694723400150000000"}]}]}]}`,
			contentType:    "application/json",
			hasSecret:      true,
			expectedStatus: http.StatusOK,
			tracesExpected: true,
			isJSON:         true,
			addSignature:   true, // Add signature for valid request
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

			secret := ""
			if tc.hasSecret {
				secret = testSecret
			}
			cfg := &Config{
				Endpoint: "localhost:0",
				Traces: SignalConfig{
					Secret: secret,
				},
			}

			recv := newTestTracesReceiverForTest(t, cfg, nextConsumer)

			// Create request
			body := io.NopCloser(bytes.NewBufferString(tc.payload))
			req := httptest.NewRequest(http.MethodPost, "http://localhost/traces", body)

			req.Header.Set("Content-Type", tc.contentType)

			if tc.addSignature {
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
			Endpoint: "localhost:0",
			Traces: SignalConfig{
				Secret: "",
			},
		}

		recv := newTestTracesReceiverForTest(t, cfg, sink)

		// Sample JSON trace from testdata
		payload := `{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"vercel-function"}}]},"scopeSpans":[{"scope":{"name":"vercel"},"spans":[{"traceId":"7bba9f33312b3dbb8b2c2c62bb7abe2d","spanId":"086e83747d0e381e","name":"GET /api/users","kind":2,"startTimeUnixNano":"1694723400000000000","endTimeUnixNano":"1694723400150000000"}]}]}]}`

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
			Endpoint: "localhost:0",
			Traces: SignalConfig{
				Secret: "",
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

func newTestTracesReceiverForTest(t *testing.T, cfg *Config, nextConsumer consumer.Traces) *vercelReceiver {
	set := receivertest.NewNopSettings(Type)
	set.Logger = zaptest.NewLogger(t)

	r := newVercelReceiver(set, cfg)
	err := r.RegisterTracesConsumer(nextConsumer, set)
	require.NoError(t, err)
	return r
}
func TestConvertSpeedInsightsToPdata(t *testing.T) {
	testCases := []struct {
		name         string
		insights     []speedInsight
		expectedFunc func(*testing.T) pmetric.Metrics
	}{
		{
			name: "single metric entry",
			insights: []speedInsight{
				{
					Schema:     "vercel.speed_insights.v1",
					Timestamp:  "2023-09-14T15:30:00.000Z",
					ProjectID:  "Qmc52npNy86S8VV4Mt8a8dP1LEkRNbgosW3pBCQytkcgf2",
					OwnerID:    "team_nLlpyC6REAqxydlFKbrMDlud",
					DeviceID:   12345,
					MetricType: "CLS",
					Value:      0.1,
					Origin:     "https://example.com",
					Path:       "/dashboard",
				},
			},
			expectedFunc: func(t *testing.T) pmetric.Metrics {
				expected := pmetric.NewMetrics()
				rm := expected.ResourceMetrics().AppendEmpty()
				res := rm.Resource()
				res.Attributes().PutStr("project.id", "Qmc52npNy86S8VV4Mt8a8dP1LEkRNbgosW3pBCQytkcgf2")
				res.Attributes().PutStr("owner.id", "team_nLlpyC6REAqxydlFKbrMDlud")
				res.Attributes().PutInt("device.id", 12345)
				res.Attributes().PutStr("origin", "https://example.com")

				sm := rm.ScopeMetrics().AppendEmpty()
				metric := sm.Metrics().AppendEmpty()
				metric.SetName("vercel.speed_insights.CLS")
				metric.SetDescription("Vercel Speed Insights metric: CLS")
				metric.SetUnit("1")

				gauge := metric.SetEmptyGauge()
				dp := gauge.DataPoints().AppendEmpty()

				ts, _ := time.Parse(time.RFC3339, "2023-09-14T15:30:00.000Z")
				dp.SetTimestamp(pcommon.NewTimestampFromTime(ts))
				dp.SetDoubleValue(0.1)
				dp.Attributes().PutStr("path", "/dashboard")

				return expected
			},
		},
		{
			name: "multiple metrics different types",
			insights: []speedInsight{
				{
					MetricType: "CLS",
					Value:      0.1,
					ProjectID:  "proj1",
					OwnerID:    "owner1",
					DeviceID:   12345,
					Origin:     "https://example.com",
					Path:       "/dashboard",
					Timestamp:  "2023-09-14T15:30:00.000Z",
				},
				{
					MetricType: "LCP",
					Value:      2.5,
					ProjectID:  "proj1",
					OwnerID:    "owner1",
					DeviceID:   12345,
					Origin:     "https://example.com",
					Path:       "/dashboard",
					Timestamp:  "2023-09-14T15:30:05.000Z",
				},
				{
					MetricType: "FID",
					Value:      150.0,
					ProjectID:  "proj1",
					OwnerID:    "owner1",
					DeviceID:   12345,
					Origin:     "https://example.com",
					Path:       "/dashboard",
					Timestamp:  "2023-09-14T15:30:10.000Z",
				},
			},
			expectedFunc: func(t *testing.T) pmetric.Metrics {
				expected := pmetric.NewMetrics()
				rm := expected.ResourceMetrics().AppendEmpty()
				res := rm.Resource()
				res.Attributes().PutStr("project.id", "proj1")
				res.Attributes().PutStr("owner.id", "owner1")
				res.Attributes().PutInt("device.id", 12345)
				res.Attributes().PutStr("origin", "https://example.com")

				sm := rm.ScopeMetrics().AppendEmpty()

				// CLS metric
				clsMetric := sm.Metrics().AppendEmpty()
				clsMetric.SetName("vercel.speed_insights.CLS")
				clsMetric.SetDescription("Vercel Speed Insights metric: CLS")
				clsMetric.SetUnit("1")
				clsGauge := clsMetric.SetEmptyGauge()
				clsDp := clsGauge.DataPoints().AppendEmpty()
				ts1, _ := time.Parse(time.RFC3339, "2023-09-14T15:30:00.000Z")
				clsDp.SetTimestamp(pcommon.NewTimestampFromTime(ts1))
				clsDp.SetDoubleValue(0.1)
				clsDp.Attributes().PutStr("path", "/dashboard")

				// LCP metric
				lcpMetric := sm.Metrics().AppendEmpty()
				lcpMetric.SetName("vercel.speed_insights.LCP")
				lcpMetric.SetDescription("Vercel Speed Insights metric: LCP")
				lcpMetric.SetUnit("1")
				lcpGauge := lcpMetric.SetEmptyGauge()
				lcpDp := lcpGauge.DataPoints().AppendEmpty()
				ts2, _ := time.Parse(time.RFC3339, "2023-09-14T15:30:05.000Z")
				lcpDp.SetTimestamp(pcommon.NewTimestampFromTime(ts2))
				lcpDp.SetDoubleValue(2.5)
				lcpDp.Attributes().PutStr("path", "/dashboard")

				// FID metric
				fidMetric := sm.Metrics().AppendEmpty()
				fidMetric.SetName("vercel.speed_insights.FID")
				fidMetric.SetDescription("Vercel Speed Insights metric: FID")
				fidMetric.SetUnit("ms")
				fidGauge := fidMetric.SetEmptyGauge()
				fidDp := fidGauge.DataPoints().AppendEmpty()
				ts3, _ := time.Parse(time.RFC3339, "2023-09-14T15:30:10.000Z")
				fidDp.SetTimestamp(pcommon.NewTimestampFromTime(ts3))
				fidDp.SetDoubleValue(150.0)
				fidDp.Attributes().PutStr("path", "/dashboard")

				return expected
			},
		},
		{
			name: "metric with additional attributes",
			insights: []speedInsight{
				{
					MetricType:      "TTFB",
					Value:           500.0,
					ProjectID:       "proj1",
					OwnerID:         "owner1",
					DeviceID:        67890,
					Origin:          "https://example.com",
					Path:            "/api/users",
					Route:           "/api/users",
					Country:         "US",
					Region:          "CA",
					City:            "San Francisco",
					OSName:          "MacOS",
					OSVersion:       "14.0",
					ClientName:      "Chrome",
					ClientType:      "browser",
					ClientVersion:   "120.0",
					DeviceType:      "desktop",
					DeviceBrand:     "Apple",
					ConnectionSpeed: "4g",
					BrowserEngine:   "Blink",
					SDKVersion:      "1.0.0",
					Timestamp:       "2023-09-14T15:30:00.000Z",
				},
			},
			expectedFunc: func(t *testing.T) pmetric.Metrics {
				expected := pmetric.NewMetrics()
				rm := expected.ResourceMetrics().AppendEmpty()
				res := rm.Resource()
				res.Attributes().PutStr("project.id", "proj1")
				res.Attributes().PutStr("owner.id", "owner1")
				res.Attributes().PutInt("device.id", 67890)
				res.Attributes().PutStr("origin", "https://example.com")
				res.Attributes().PutStr("country", "US")
				res.Attributes().PutStr("region", "CA")
				res.Attributes().PutStr("city", "San Francisco")
				res.Attributes().PutStr("os.name", "MacOS")
				res.Attributes().PutStr("client.name", "Chrome")
				res.Attributes().PutStr("device.type", "desktop")
				res.Attributes().PutStr("deployment.id", "")

				sm := rm.ScopeMetrics().AppendEmpty()
				metric := sm.Metrics().AppendEmpty()
				metric.SetName("vercel.speed_insights.TTFB")
				metric.SetDescription("Vercel Speed Insights metric: TTFB")
				metric.SetUnit("1")

				gauge := metric.SetEmptyGauge()
				dp := gauge.DataPoints().AppendEmpty()

				ts, _ := time.Parse(time.RFC3339, "2023-09-14T15:30:00.000Z")
				dp.SetTimestamp(pcommon.NewTimestampFromTime(ts))
				dp.SetDoubleValue(500.0)

				attrs := dp.Attributes()
				attrs.PutStr("path", "/api/users")
				attrs.PutStr("route", "/api/users")
				attrs.PutStr("os.version", "14.0")
				attrs.PutStr("client.version", "120.0")
				attrs.PutStr("device.brand", "Apple")
				attrs.PutStr("connection.speed", "4g")
				attrs.PutStr("browser.engine", "Blink")
				attrs.PutStr("sdk.version", "1.0.0")

				return expected
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			expected := tc.expectedFunc(t)
			actual := convertSpeedInsightsToPdata(tc.insights)

			// Compare resource metrics count
			require.Equal(t, expected.ResourceMetrics().Len(), actual.ResourceMetrics().Len())

			// Compare each metric
			for i := 0; i < expected.ResourceMetrics().Len(); i++ {
				expectedRM := expected.ResourceMetrics().At(i)
				actualRM := actual.ResourceMetrics().At(i)

				// Compare resource attributes
				expectedResAttrs := expectedRM.Resource().Attributes()
				actualResAttrs := actualRM.Resource().Attributes()
				expectedResAttrs.Range(func(k string, v pcommon.Value) bool {
					actualVal, exists := actualResAttrs.Get(k)
					if k == "deployment.id" && !exists {
						// deployment.id might not be set if empty
						return true
					}
					require.True(t, exists, "Missing resource attribute: %s", k)
					if v.Type() == pcommon.ValueTypeStr {
						assert.Equal(t, v.Str(), actualVal.Str(), "Resource attribute value mismatch: %s", k)
					} else if v.Type() == pcommon.ValueTypeInt {
						assert.Equal(t, v.Int(), actualVal.Int(), "Resource attribute value mismatch: %s", k)
					}
					return true
				})

				// Compare metrics count
				expectedSM := expectedRM.ScopeMetrics().At(0)
				actualSM := actualRM.ScopeMetrics().At(0)
				require.Equal(t, expectedSM.Metrics().Len(), actualSM.Metrics().Len())

				// Compare each metric
				for j := 0; j < expectedSM.Metrics().Len(); j++ {
					expectedMetric := expectedSM.Metrics().At(j)
					actualMetric := actualSM.Metrics().At(j)

					assert.Equal(t, expectedMetric.Name(), actualMetric.Name())
					assert.Equal(t, expectedMetric.Description(), actualMetric.Description())
					assert.Equal(t, expectedMetric.Unit(), actualMetric.Unit())

					// Compare data points
					if expectedMetric.Type() == pmetric.MetricTypeGauge {
						expectedGauge := expectedMetric.Gauge()
						actualGauge := actualMetric.Gauge()

						require.Equal(t, expectedGauge.DataPoints().Len(), actualGauge.DataPoints().Len())

						for k := 0; k < expectedGauge.DataPoints().Len(); k++ {
							expectedDp := expectedGauge.DataPoints().At(k)
							actualDp := actualGauge.DataPoints().At(k)

							assert.Equal(t, expectedDp.Timestamp().AsTime().Unix(), actualDp.Timestamp().AsTime().Unix())
							assert.Equal(t, expectedDp.DoubleValue(), actualDp.DoubleValue())

							// Compare data point attributes
							expectedDpAttrs := expectedDp.Attributes()
							actualDpAttrs := actualDp.Attributes()
							expectedDpAttrs.Range(func(key string, val pcommon.Value) bool {
								actualVal, exists := actualDpAttrs.Get(key)
								require.True(t, exists, "Missing data point attribute: %s", key)
								assert.Equal(t, val.AsString(), actualVal.AsString())
								return true
							})
						}
					}
				}
			}
		})
	}
}

func TestHandleSpeedInsights(t *testing.T) {
	testCases := []struct {
		name               string
		payload            string
		hasSecret          bool
		consumerFailure    bool
		permanentFailure   bool
		expectedStatusCode int
		metricExpected     bool
		addSignature       bool // whether to actually add signature to request
	}{
		{
			name:               "missing signature with secret",
			payload:            `[{"schema":"vercel.speed_insights.v1","metricType":"CLS","value":0.1}]`,
			hasSecret:          true,
			expectedStatusCode: http.StatusUnauthorized,
			metricExpected:     false,
			addSignature:       false, // Don't add signature even though hasSecret is true
		},
		{
			name:               "invalid JSON payload",
			payload:            `[{"schema":"vercel.speed_insights.v1","metricType":"CLS","value":0.1`,
			hasSecret:          false,
			expectedStatusCode: http.StatusBadRequest,
			metricExpected:     false,
		},
		{
			name:               "valid request",
			payload:            `[{"schema":"vercel.speed_insights.v1","timestamp":"2023-09-14T15:30:00.000Z","metricType":"CLS","value":0.1,"origin":"https://example.com","path":"/dashboard"}]`,
			hasSecret:          false,
			expectedStatusCode: http.StatusOK,
			metricExpected:     true,
		},
		{
			name:               "consumer fails",
			payload:            `[{"schema":"vercel.speed_insights.v1","metricType":"CLS","value":0.1}]`,
			hasSecret:          false,
			consumerFailure:    true,
			expectedStatusCode: http.StatusInternalServerError,
			metricExpected:     false,
		},
		{
			name:               "NDJSON format",
			payload:            `{"schema":"vercel.speed_insights.v1","timestamp":"2023-09-14T15:30:00.000Z","metricType":"CLS","value":0.1}` + "\n" + `{"schema":"vercel.speed_insights.v1","timestamp":"2023-09-14T15:30:05.000Z","metricType":"LCP","value":2.5}`,
			hasSecret:          false,
			expectedStatusCode: http.StatusOK,
			metricExpected:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var consumer consumer.Metrics
			var sink *consumertest.MetricsSink

			if tc.consumerFailure {
				if tc.permanentFailure {
					consumer = consumertest.NewErr(consumererror.NewPermanent(errors.New("permanent error")))
				} else {
					consumer = consumertest.NewErr(errors.New("consumer failed"))
				}
			} else {
				sink = &consumertest.MetricsSink{}
				consumer = sink
			}

			secret := ""
			if tc.hasSecret {
				secret = testSecret
			}
			cfg := &Config{
				Endpoint: "localhost:0",
				SpeedInsights: SignalConfig{
					Secret: secret,
				},
			}

			recv := newTestSpeedInsightsReceiver(t, cfg, consumer)

			// Create request
			body := io.NopCloser(bytes.NewBufferString(tc.payload))
			req := httptest.NewRequest(http.MethodPost, "http://localhost/speed-insights", body)

			if tc.addSignature {
				signature := createSignature([]byte(testSecret), []byte(tc.payload))
				req.Header.Set(xVercelSignatureHeader, signature)
			}

			rec := httptest.NewRecorder()

			recv.handleSpeedInsights(rec, req)

			assert.Equal(t, tc.expectedStatusCode, rec.Code, "Status code mismatch")

			if !tc.consumerFailure && sink != nil {
				if tc.metricExpected {
					time.Sleep(10 * time.Millisecond)
					assert.Greater(t, sink.DataPointCount(), 0, "Expected metrics but got none")
				} else {
					assert.Equal(t, 0, sink.DataPointCount(), "Did not expect metrics but got some")
				}
			}
		})
	}
}

func newTestSpeedInsightsReceiver(t *testing.T, cfg *Config, nextConsumer consumer.Metrics) *vercelReceiver {
	set := receivertest.NewNopSettings(Type)
	set.Logger = zaptest.NewLogger(t)

	r := newVercelReceiver(set, cfg)
	err := r.RegisterMetricsConsumer(nextConsumer, set)
	require.NoError(t, err)
	return r
}
func TestConvertWebAnalyticsToPdata(t *testing.T) {
	testCases := []struct {
		name         string
		events       []webAnalyticsEvent
		expectedFunc func(*testing.T) plog.Logs
	}{
		{
			name: "pageview event",
			events: []webAnalyticsEvent{
				{
					Schema:         "vercel.analytics.v1",
					EventType:      "pageview",
					Timestamp:      1694723400000,
					ProjectID:      "Qmc52npNy86S8VV4Mt8a8dP1LEkRNbgosW3pBCQytkcgf2",
					OwnerID:        "team_nLlpyC6REAqxydlFKbrMDlud",
					DataSourceName: "web-analytics",
					SessionID:      12345,
					DeviceID:       67890,
					Origin:         "https://example.com",
					Path:           "/dashboard",
				},
			},
			expectedFunc: func(t *testing.T) plog.Logs {
				expected := plog.NewLogs()
				rl := expected.ResourceLogs().AppendEmpty()
				sl := rl.ScopeLogs().AppendEmpty()

				lr := sl.LogRecords().AppendEmpty()
				lr.SetTimestamp(pcommon.NewTimestampFromTime(time.Unix(0, 1694723400000*int64(time.Millisecond))))
				lr.SetSeverityNumber(plog.SeverityNumberInfo)
				lr.SetSeverityText("INFO")

				// Body should be eventType when eventName is empty
				pcommon.NewValueStr("pageview").CopyTo(lr.Body())

				attrs := lr.Attributes()
				attrs.PutStr("event.type", "pageview")
				attrs.PutStr("data.source.name", "web-analytics")
				attrs.PutInt("session.id", 12345)
				attrs.PutStr("origin", "https://example.com")
				attrs.PutStr("path", "/dashboard")

				return expected
			},
		},
		{
			name: "custom event with eventName and eventData",
			events: []webAnalyticsEvent{
				{
					Schema:         "vercel.analytics.v1",
					EventType:      "event",
					EventName:      "button_click",
					EventData:      `{"button": "signup"}`,
					Timestamp:      1694723405000,
					ProjectID:      "Qmc52npNy86S8VV4Mt8a8dP1LEkRNbgosW3pBCQytkcgf2",
					OwnerID:        "team_nLlpyC6REAqxydlFKbrMDlud",
					DataSourceName: "web-analytics",
					SessionID:      12345,
					DeviceID:       67890,
					Origin:         "https://example.com",
					Path:           "/signup",
				},
			},
			expectedFunc: func(t *testing.T) plog.Logs {
				expected := plog.NewLogs()
				rl := expected.ResourceLogs().AppendEmpty()
				sl := rl.ScopeLogs().AppendEmpty()

				lr := sl.LogRecords().AppendEmpty()
				lr.SetTimestamp(pcommon.NewTimestampFromTime(time.Unix(0, 1694723405000*int64(time.Millisecond))))
				lr.SetSeverityNumber(plog.SeverityNumberInfo)
				lr.SetSeverityText("INFO")

				// Body should be eventName when available
				pcommon.NewValueStr("button_click").CopyTo(lr.Body())

				attrs := lr.Attributes()
				attrs.PutStr("event.type", "event")
				attrs.PutStr("event.name", "button_click")
				attrs.PutStr("event.data", `{"button": "signup"}`)
				attrs.PutStr("data.source.name", "web-analytics")
				attrs.PutInt("session.id", 12345)
				attrs.PutStr("origin", "https://example.com")
				attrs.PutStr("path", "/signup")

				return expected
			},
		},
		{
			name: "multiple events",
			events: []webAnalyticsEvent{
				{
					EventType: "pageview",
					Timestamp: 1694723400000,
					Origin:    "https://example.com",
					Path:      "/home",
					SessionID: 100,
				},
				{
					EventType: "event",
					EventName: "click",
					Timestamp: 1694723401000,
					Origin:    "https://example.com",
					Path:      "/home",
					SessionID: 100,
					Referrer:  "https://google.com",
				},
			},
			expectedFunc: func(t *testing.T) plog.Logs {
				expected := plog.NewLogs()
				rl := expected.ResourceLogs().AppendEmpty()
				sl := rl.ScopeLogs().AppendEmpty()

				lr1 := sl.LogRecords().AppendEmpty()
				lr1.SetTimestamp(pcommon.NewTimestampFromTime(time.Unix(0, 1694723400000*int64(time.Millisecond))))
				lr1.SetSeverityNumber(plog.SeverityNumberInfo)
				lr1.SetSeverityText("INFO")
				pcommon.NewValueStr("pageview").CopyTo(lr1.Body())
				attrs1 := lr1.Attributes()
				attrs1.PutStr("event.type", "pageview")
				attrs1.PutStr("origin", "https://example.com")
				attrs1.PutStr("path", "/home")
				attrs1.PutInt("session.id", 100)

				lr2 := sl.LogRecords().AppendEmpty()
				lr2.SetTimestamp(pcommon.NewTimestampFromTime(time.Unix(0, 1694723401000*int64(time.Millisecond))))
				lr2.SetSeverityNumber(plog.SeverityNumberInfo)
				lr2.SetSeverityText("INFO")
				pcommon.NewValueStr("click").CopyTo(lr2.Body())
				attrs2 := lr2.Attributes()
				attrs2.PutStr("event.type", "event")
				attrs2.PutStr("event.name", "click")
				attrs2.PutStr("origin", "https://example.com")
				attrs2.PutStr("path", "/home")
				attrs2.PutInt("session.id", 100)
				attrs2.PutStr("referrer", "https://google.com")

				return expected
			},
		},
		{
			name: "event with all attributes",
			events: []webAnalyticsEvent{
				{
					EventType:            "pageview",
					EventName:            "page_loaded",
					EventData:            `{"duration": 1234}`,
					Timestamp:            1694723400000,
					ProjectID:            "proj1",
					OwnerID:              "owner1",
					DataSourceName:       "web-analytics",
					SessionID:            12345,
					DeviceID:             67890,
					Origin:               "https://example.com",
					Path:                 "/dashboard",
					Referrer:             "https://google.com",
					QueryParams:          "?utm_source=google",
					Route:                "/dashboard",
					Country:              "US",
					Region:               "CA",
					City:                 "San Francisco",
					OSName:               "MacOS",
					OSVersion:            "14.0",
					ClientName:           "Chrome",
					ClientType:           "browser",
					ClientVersion:        "120.0",
					DeviceType:           "desktop",
					DeviceBrand:          "Apple",
					DeviceModel:          "MacBook Pro",
					BrowserEngine:        "Blink",
					BrowserEngineVersion: "120.0",
					SDKVersion:           "1.0.0",
					SDKName:              "vercel-web",
					VercelEnvironment:    "production",
					VercelURL:            "https://example.vercel.app",
					Flags:                "feature-flag-1",
					Deployment:           "dpl_123",
				},
			},
			expectedFunc: func(t *testing.T) plog.Logs {
				expected := plog.NewLogs()
				rl := expected.ResourceLogs().AppendEmpty()
				sl := rl.ScopeLogs().AppendEmpty()

				lr := sl.LogRecords().AppendEmpty()
				lr.SetTimestamp(pcommon.NewTimestampFromTime(time.Unix(0, 1694723400000*int64(time.Millisecond))))
				lr.SetSeverityNumber(plog.SeverityNumberInfo)
				lr.SetSeverityText("INFO")
				pcommon.NewValueStr("page_loaded").CopyTo(lr.Body())

				attrs := lr.Attributes()
				attrs.PutStr("event.type", "pageview")
				attrs.PutStr("event.name", "page_loaded")
				attrs.PutStr("event.data", `{"duration": 1234}`)
				attrs.PutStr("data.source.name", "web-analytics")
				attrs.PutInt("session.id", 12345)
				attrs.PutStr("origin", "https://example.com")
				attrs.PutStr("path", "/dashboard")
				attrs.PutStr("referrer", "https://google.com")
				attrs.PutStr("query.params", "?utm_source=google")
				attrs.PutStr("route", "/dashboard")
				attrs.PutStr("city", "San Francisco")
				attrs.PutStr("os.name", "MacOS")
				attrs.PutStr("os.version", "14.0")
				attrs.PutStr("client.name", "Chrome")
				attrs.PutStr("client.type", "browser")
				attrs.PutStr("client.version", "120.0")
				attrs.PutStr("device.type", "desktop")
				attrs.PutStr("device.brand", "Apple")
				attrs.PutStr("device.model", "MacBook Pro")
				attrs.PutStr("browser.engine", "Blink")
				attrs.PutStr("browser.engine.version", "120.0")
				attrs.PutStr("sdk.version", "1.0.0")
				attrs.PutStr("sdk.name", "vercel-web")
				attrs.PutStr("vercel.environment", "production")
				attrs.PutStr("vercel.url", "https://example.vercel.app")
				attrs.PutStr("flags", "feature-flag-1")
				attrs.PutStr("deployment.id", "dpl_123")

				return expected
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			expected := tc.expectedFunc(t)
			actual := convertWebAnalyticsToPdata(tc.events)

			// Compare log record count
			require.Equal(t, expected.LogRecordCount(), actual.LogRecordCount(), "Log record count mismatch")

			// Compare each log record
			expectedRL := expected.ResourceLogs().At(0)
			actualRL := actual.ResourceLogs().At(0)

			require.Equal(t, expectedRL.ScopeLogs().Len(), actualRL.ScopeLogs().Len())

			for i := 0; i < expectedRL.ScopeLogs().Len(); i++ {
				expectedSL := expectedRL.ScopeLogs().At(i)
				actualSL := actualRL.ScopeLogs().At(i)

				require.Equal(t, expectedSL.LogRecords().Len(), actualSL.LogRecords().Len())

				for j := 0; j < expectedSL.LogRecords().Len(); j++ {
					expectedLR := expectedSL.LogRecords().At(j)
					actualLR := actualSL.LogRecords().At(j)

					// Compare timestamps
					assert.Equal(t, expectedLR.Timestamp().AsTime().Unix(), actualLR.Timestamp().AsTime().Unix())

					// Compare severity
					assert.Equal(t, expectedLR.SeverityNumber(), actualLR.SeverityNumber())
					assert.Equal(t, expectedLR.SeverityText(), actualLR.SeverityText())

					// Compare body
					assert.Equal(t, expectedLR.Body().Str(), actualLR.Body().Str())

					// Compare attributes
					expectedAttrs := expectedLR.Attributes()
					actualAttrs := actualLR.Attributes()

					expectedAttrs.Range(func(k string, v pcommon.Value) bool {
						actualVal, exists := actualAttrs.Get(k)
						require.True(t, exists, "Missing attribute: %s", k)
						assert.Equal(t, v.Str(), actualVal.Str(), "Attribute value mismatch: %s", k)
						return true
					})
				}
			}
		})
	}
}

func TestHandleWebAnalytics(t *testing.T) {
	testCases := []struct {
		name               string
		payload            string
		hasSecret          bool
		consumerFailure    bool
		permanentFailure   bool
		expectedStatusCode int
		logExpected        bool
		addSignature       bool // whether to actually add signature to request
	}{
		{
			name:               "missing signature with secret",
			payload:            `[{"schema":"vercel.analytics.v1","eventType":"pageview","timestamp":1694723400000}]`,
			hasSecret:          true,
			expectedStatusCode: http.StatusUnauthorized,
			logExpected:        false,
			addSignature:       false, // Don't add signature even though hasSecret is true
		},
		{
			name:               "invalid JSON payload",
			payload:            `[{"schema":"vercel.analytics.v1","eventType":"pageview","timestamp":1694723400000`,
			hasSecret:          false,
			expectedStatusCode: http.StatusBadRequest,
			logExpected:        false,
		},
		{
			name:               "valid request",
			payload:            `[{"schema":"vercel.analytics.v1","eventType":"pageview","timestamp":1694723400000,"origin":"https://example.com","path":"/dashboard"}]`,
			hasSecret:          false,
			expectedStatusCode: http.StatusOK,
			logExpected:        true,
		},
		{
			name:               "consumer fails",
			payload:            `[{"schema":"vercel.analytics.v1","eventType":"pageview","timestamp":1694723400000}]`,
			hasSecret:          false,
			consumerFailure:    true,
			expectedStatusCode: http.StatusInternalServerError,
			logExpected:        false,
		},
		{
			name:               "NDJSON format",
			payload:            `{"schema":"vercel.analytics.v1","eventType":"pageview","timestamp":1694723400000}` + "\n" + `{"schema":"vercel.analytics.v1","eventType":"event","eventName":"click","timestamp":1694723401000}`,
			hasSecret:          false,
			expectedStatusCode: http.StatusOK,
			logExpected:        true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var nextConsumer consumer.Logs
			var sink *consumertest.LogsSink

			if tc.consumerFailure {
				if tc.permanentFailure {
					nextConsumer = consumertest.NewErr(consumererror.NewPermanent(errors.New("permanent error")))
				} else {
					nextConsumer = consumertest.NewErr(errors.New("consumer failed"))
				}
			} else {
				sink = &consumertest.LogsSink{}
				nextConsumer = sink
			}

			cfg := &Config{
				Endpoint: "localhost:0",
				WebAnalytics: SignalConfig{
					Secret: func() string {
						if tc.hasSecret {
							return testSecret
						} else {
							return ""
						}
					}(),
				},
			}

			recv := newTestWebAnalyticsReceiverForTest(t, cfg, nextConsumer)

			// Create request
			body := io.NopCloser(bytes.NewBufferString(tc.payload))
			req := httptest.NewRequest(http.MethodPost, "http://localhost/analytics", body)

			if tc.addSignature {
				signature := createSignature([]byte(testSecret), []byte(tc.payload))
				req.Header.Set(xVercelSignatureHeader, signature)
			}

			rec := httptest.NewRecorder()

			recv.handleWebAnalytics(rec, req)

			assert.Equal(t, tc.expectedStatusCode, rec.Code, "Status code mismatch")

			if !tc.consumerFailure && sink != nil {
				if tc.logExpected {
					time.Sleep(10 * time.Millisecond)
					assert.Greater(t, sink.LogRecordCount(), 0, "Expected log records but got none")
				} else {
					assert.Equal(t, 0, sink.LogRecordCount(), "Did not expect log records but got some")
				}
			}
		})
	}
}

func newTestWebAnalyticsReceiverForTest(t *testing.T, cfg *Config, nextConsumer consumer.Logs) *vercelReceiver {
	set := receivertest.NewNopSettings(Type)
	set.Logger = zaptest.NewLogger(t)

	r := newVercelReceiver(set, cfg)
	err := r.RegisterLogsConsumer(nextConsumer, set)
	require.NoError(t, err)
	return r
}
