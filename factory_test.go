// Copyright The OpenTelemetry Authors

// SPDX-License-Identifier: Apache-2.0

package vercelreceiver

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/receiver/receivertest"
)

func TestType(t *testing.T) {
	factory := NewFactory()
	ft := factory.Type()
	require.Equal(t, Type, ft)
}

func TestCreateLogs(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	_, err := NewFactory().CreateLogs(
		t.Context(),
		receivertest.NewNopSettings(Type),
		cfg,
		nil,
	)
	require.NoError(t, err)
}

func TestCreateTraces(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	_, err := NewFactory().CreateTraces(
		t.Context(),
		receivertest.NewNopSettings(Type),
		cfg,
		nil,
	)
	require.NoError(t, err)
}

func TestCreateMetrics(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	_, err := NewFactory().CreateMetrics(
		t.Context(),
		receivertest.NewNopSettings(Type),
		cfg,
		nil,
	)
	require.NoError(t, err)
}

func TestCreateDefaultConfig(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()

	expected := &Config{
		Logs:          LogsConfig{},
		Traces:        TracesConfig{},
		SpeedInsights: SpeedInsightsConfig{},
		WebAnalytics:  WebAnalyticsConfig{},
	}

	require.Equal(t, expected, cfg)
}

func TestMultipleLogsReceivers(t *testing.T) {
	cfg := createDefaultConfig().(*Config)

	// Test that we can create multiple logs receivers (logs and web_analytics)
	_, err := NewFactory().CreateLogs(
		t.Context(),
		receivertest.NewNopSettings(Type),
		cfg,
		nil,
	)
	require.NoError(t, err)
}
