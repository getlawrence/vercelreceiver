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
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.uber.org/zap/zaptest"
)

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
				WebAnalytics: WebAnalyticsConfig{
					Endpoint: "localhost:0",
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

func newTestWebAnalyticsReceiverForTest(t *testing.T, cfg *Config, nextConsumer consumer.Logs) *webAnalyticsReceiver {
	set := receivertest.NewNopSettings(Type)
	set.Logger = zaptest.NewLogger(t)

	r, err := newWebAnalyticsReceiver(set, cfg, nextConsumer)
	require.NoError(t, err)
	return r
}
