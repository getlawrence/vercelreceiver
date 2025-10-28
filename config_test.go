package vercelreceiver

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidate(t *testing.T) {
	cases := []struct {
		name           string
		config         Config
		expectedErr    string
		expectedRoutes *struct {
			logs          string
			traces        string
			speedInsights string
			webAnalytics  string
		}
	}{
		{
			name: "Valid config with endpoint",
			config: Config{
				Endpoint: "0.0.0.0:9999",
				Secret:   "test-secret",
				Logs: SignalConfig{
					Secret: "test-secret",
				},
				Traces: SignalConfig{
					Secret: "test-secret",
				},
				SpeedInsights: SignalConfig{
					Secret: "test-secret",
				},
				WebAnalytics: SignalConfig{
					Secret: "test-secret",
				},
			},
		},
		{
			name: "Valid config with empty endpoint (uses default)",
			config: Config{
				Logs:          SignalConfig{},
				Traces:        SignalConfig{},
				SpeedInsights: SignalConfig{},
				WebAnalytics:  SignalConfig{},
			},
		},
		{
			name: "Valid config with custom routes",
			config: Config{
				Endpoint: "localhost:8080",
				Logs: SignalConfig{
					Route:  "/custom-logs",
					Secret: "logs-secret",
				},
				Traces: SignalConfig{
					Route: "/custom-traces",
				},
				SpeedInsights: SignalConfig{
					Route: "/custom-metrics",
				},
				WebAnalytics: SignalConfig{
					Route: "/custom-analytics",
				},
			},
			expectedRoutes: &struct {
				logs          string
				traces        string
				speedInsights string
				webAnalytics  string
			}{
				logs:          "/custom-logs",
				traces:        "/custom-traces",
				speedInsights: "/custom-metrics",
				webAnalytics:  "/custom-analytics",
			},
		},
		{
			name: "Invalid endpoint - missing port",
			config: Config{
				Endpoint: "localhost",
			},
			expectedErr: "invalid endpoint",
		},
		{
			name: "Invalid endpoint - invalid port",
			config: Config{
				Endpoint: "localhost:99999",
			},
			expectedErr: "invalid endpoint",
		},
		{
			name: "Invalid endpoint - empty host",
			config: Config{
				Endpoint: ":8080",
			},
			expectedErr: "invalid endpoint",
		},
		{
			name: "Invalid endpoint - malformed",
			config: Config{
				Endpoint: "not-a-valid-endpoint",
			},
			expectedErr: "invalid endpoint",
		},
		{
			name: "Valid config with different endpoint formats",
			config: Config{
				Endpoint: "[::1]:8081",
			},
		},
		{
			name: "Valid config sets default routes",
			config: Config{
				Endpoint: "localhost:8080",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()
			if tc.expectedErr != "" {
				require.ErrorContains(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
				// Verify routes are set correctly (custom or default)
				if tc.expectedRoutes != nil {
					require.Equal(t, tc.expectedRoutes.logs, tc.config.Logs.Route)
					require.Equal(t, tc.expectedRoutes.traces, tc.config.Traces.Route)
					require.Equal(t, tc.expectedRoutes.speedInsights, tc.config.SpeedInsights.Route)
					require.Equal(t, tc.expectedRoutes.webAnalytics, tc.config.WebAnalytics.Route)
				} else {
					// Verify default routes are set
					require.Equal(t, "/logs", tc.config.Logs.Route)
					require.Equal(t, "/traces", tc.config.Traces.Route)
					require.Equal(t, "/speed-insights", tc.config.SpeedInsights.Route)
					require.Equal(t, "/analytics", tc.config.WebAnalytics.Route)
				}
			}
		})
	}
}

func TestValidateEndpoint(t *testing.T) {
	cases := []struct {
		name        string
		endpoint    string
		expectedErr string
	}{
		{
			name:     "Valid endpoint with IP",
			endpoint: "127.0.0.1:8080",
		},
		{
			name:     "Valid endpoint with localhost",
			endpoint: "localhost:8080",
		},
		{
			name:     "Valid endpoint with IPv6",
			endpoint: "[::1]:8080",
		},
		{
			name:     "Valid endpoint with 0.0.0.0",
			endpoint: "0.0.0.0:8080",
		},
		{
			name:        "Empty endpoint",
			endpoint:    "",
			expectedErr: "endpoint cannot be empty",
		},
		{
			name:        "Missing port",
			endpoint:    "localhost",
			expectedErr: "failed to split endpoint into 'host:port' pair",
		},
		{
			name:        "Empty host",
			endpoint:    ":8080",
			expectedErr: "host cannot be empty",
		},
		{
			name:        "Empty port",
			endpoint:    "localhost:",
			expectedErr: "port cannot be empty",
		},
		{
			name:        "Invalid port number",
			endpoint:    "localhost:99999",
			expectedErr: "invalid port '99999'",
		},
		{
			name:        "Non-numeric port",
			endpoint:    "localhost:abc",
			expectedErr: "invalid port 'abc'",
		},
		{
			name:        "Malformed endpoint",
			endpoint:    "not-a-valid-endpoint",
			expectedErr: "failed to split endpoint into 'host:port' pair",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateEndpoint(tc.endpoint)
			if tc.expectedErr != "" {
				require.ErrorContains(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
