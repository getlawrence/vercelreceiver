// Copyright The OpenTelemetry Authors

// SPDX-License-Identifier: Apache-2.0

package vercelreceiver

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidate(t *testing.T) {
	cases := []struct {
		name        string
		config      Config
		expectedErr string
	}{
		{
			name: "Valid config with all endpoints",
			config: Config{
				Logs: LogsConfig{
					Endpoint: "0.0.0.0:9999",
					Secret:   "test-secret",
				},
				Traces: TracesConfig{
					Endpoint: "0.0.0.0:9998",
					Secret:   "test-secret",
				},
				SpeedInsights: SpeedInsightsConfig{
					Endpoint: "0.0.0.0:9997",
					Secret:   "test-secret",
				},
				WebAnalytics: WebAnalyticsConfig{
					Endpoint: "0.0.0.0:9996",
					Secret:   "test-secret",
				},
			},
		},
		{
			name: "Valid config with empty endpoints",
			config: Config{
				Logs:          LogsConfig{},
				Traces:        TracesConfig{},
				SpeedInsights: SpeedInsightsConfig{},
				WebAnalytics:  WebAnalyticsConfig{},
			},
		},
		{
			name: "Valid config with partial endpoints",
			config: Config{
				Logs: LogsConfig{
					Endpoint: "localhost:8080",
					Secret:   "logs-secret",
				},
				Traces:        TracesConfig{},
				SpeedInsights: SpeedInsightsConfig{},
				WebAnalytics:  WebAnalyticsConfig{},
			},
		},
		{
			name: "Invalid logs endpoint - missing port",
			config: Config{
				Logs: LogsConfig{
					Endpoint: "localhost",
				},
			},
			expectedErr: "logs config validation failed",
		},
		{
			name: "Invalid traces endpoint - invalid port",
			config: Config{
				Traces: TracesConfig{
					Endpoint: "localhost:99999",
				},
			},
			expectedErr: "traces config validation failed",
		},
		{
			name: "Invalid speed insights endpoint - empty host",
			config: Config{
				SpeedInsights: SpeedInsightsConfig{
					Endpoint: ":8080",
				},
			},
			expectedErr: "speed_insights config validation failed",
		},
		{
			name: "Invalid web analytics endpoint - malformed",
			config: Config{
				WebAnalytics: WebAnalyticsConfig{
					Endpoint: "not-a-valid-endpoint",
				},
			},
			expectedErr: "web_analytics config validation failed",
		},
		{
			name: "Multiple invalid endpoints",
			config: Config{
				Logs: LogsConfig{
					Endpoint: "invalid",
				},
				Traces: TracesConfig{
					Endpoint: "also-invalid",
				},
			},
			expectedErr: "logs config validation failed",
		},
		{
			name: "Valid config with different port formats",
			config: Config{
				Logs: LogsConfig{
					Endpoint: "127.0.0.1:8080",
				},
				Traces: TracesConfig{
					Endpoint: "[::1]:8081",
				},
				SpeedInsights: SpeedInsightsConfig{
					Endpoint: "0.0.0.0:8082",
				},
				WebAnalytics: WebAnalyticsConfig{
					Endpoint: "localhost:8083",
				},
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
