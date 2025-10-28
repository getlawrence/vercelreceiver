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
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.uber.org/zap/zaptest"
)

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
				SpeedInsights: SpeedInsightsConfig{
					Endpoint: "localhost:0",
					Secret:   secret,
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

func newTestSpeedInsightsReceiver(t *testing.T, cfg *Config, nextConsumer consumer.Metrics) *speedInsightsReceiver {
	set := receivertest.NewNopSettings(Type)
	set.Logger = zaptest.NewLogger(t)

	r, err := newSpeedInsightsReceiver(set, cfg, nextConsumer)
	require.NoError(t, err)
	return r
}
