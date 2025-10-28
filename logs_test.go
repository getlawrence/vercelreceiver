//go:build !integration

// Copyright The OpenTelemetry Authors

// SPDX-License-Identifier: Apache-2.0

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
	}{
		{
			name:               "missing signature",
			payload:            `[{"id":"1","timestamp":1573817187330,"level":"info","message":"test"}]`,
			hasSecret:          true,
			secret:             testSecret,
			expectedStatusCode: http.StatusUnauthorized,
			logExpected:        false,
		},
		{
			name:               "invalid signature",
			payload:            `[{"id":"1","timestamp":1573817187330,"level":"info","message":"test"}]`,
			hasSecret:          true,
			secret:             testSecret,
			expectedStatusCode: http.StatusUnauthorized,
			logExpected:        false,
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
				Logs: LogsConfig{
					Endpoint: "localhost:0",
					Secret:   tc.secret,
				},
			}

			recv := newTestLogsReceiverForTest(t, cfg, nextConsumer)

			// Create request
			body := io.NopCloser(bytes.NewBufferString(tc.payload))
			req := httptest.NewRequest(http.MethodPost, "http://localhost/logs", body)

			if tc.hasSecret && tc.secret != "" {
				signature := createSignature([]byte(tc.secret), []byte(tc.payload))
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

func newTestLogsReceiverForTest(t *testing.T, cfg *Config, nextConsumer consumer.Logs) *logsReceiver {
	set := receivertest.NewNopSettings(Type)
	set.Logger = zaptest.NewLogger(t)

	r, err := newLogsReceiver(set, cfg, nextConsumer)
	require.NoError(t, err)
	return r
}
