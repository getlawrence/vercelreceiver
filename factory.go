package vercelreceiver

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
)

func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		Type,
		createDefaultConfig,
		receiver.WithLogs(createLogsReceiver, LogsStability),
		receiver.WithLogs(createWebAnalyticsReceiver, LogsStability),
		receiver.WithTraces(createTracesReceiver, TracesStability),
		receiver.WithMetrics(createSpeedInsightsReceiver, MetricsStability),
	)
}

func createLogsReceiver(
	_ context.Context,
	params receiver.Settings,
	rConf component.Config,
	consumer consumer.Logs,
) (receiver.Logs, error) {
	cfg := rConf.(*Config)
	return newLogsReceiver(params, cfg, consumer)
}

func createSpeedInsightsReceiver(
	_ context.Context,
	params receiver.Settings,
	rConf component.Config,
	consumer consumer.Metrics,
) (receiver.Metrics, error) {
	cfg := rConf.(*Config)
	return newSpeedInsightsReceiver(params, cfg, consumer)
}

func createWebAnalyticsReceiver(
	_ context.Context,
	params receiver.Settings,
	rConf component.Config,
	consumer consumer.Logs,
) (receiver.Logs, error) {
	cfg := rConf.(*Config)
	return newWebAnalyticsReceiver(params, cfg, consumer)
}

func createTracesReceiver(
	_ context.Context,
	params receiver.Settings,
	rConf component.Config,
	consumer consumer.Traces,
) (receiver.Traces, error) {
	cfg := rConf.(*Config)
	return newTracesReceiver(params, cfg, consumer)
}

func createDefaultConfig() component.Config {
	return &Config{
		Logs:          LogsConfig{},
		Traces:        TracesConfig{},
		SpeedInsights: SpeedInsightsConfig{},
		WebAnalytics:  WebAnalyticsConfig{},
	}
}
