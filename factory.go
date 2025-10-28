package vercelreceiver

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
)

var receivers = NewSharedComponents()

func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		Type,
		createDefaultConfig,
		receiver.WithLogs(createLogsReceiver, LogsStability),
		receiver.WithTraces(createTracesReceiver, TracesStability),
		receiver.WithMetrics(createMetricsReceiver, MetricsStability),
	)
}

func createLogsReceiver(
	ctx context.Context,
	params receiver.Settings,
	rConf component.Config,
	consumer consumer.Logs,
) (receiver.Logs, error) {
	cfg := rConf.(*Config)

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	var err error
	r := receivers.GetOrAdd(cfg, func() component.Component {
		dd, createErr := newVercelReceiver(params, cfg)
		err = createErr
		return dd
	})

	if err != nil {
		return nil, err
	}

	if err := r.Unwrap().(*vercelReceiver).RegisterLogsConsumer(consumer, params); err != nil {
		return nil, err
	}

	return r, nil
}

func createTracesReceiver(
	ctx context.Context,
	params receiver.Settings,
	rConf component.Config,
	consumer consumer.Traces,
) (receiver.Traces, error) {
	cfg := rConf.(*Config)

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	var err error
	r := receivers.GetOrAdd(cfg, func() component.Component {
		dd, createErr := newVercelReceiver(params, cfg)
		err = createErr
		return dd
	})

	if err != nil {
		return nil, err
	}

	if err := r.Unwrap().(*vercelReceiver).RegisterTracesConsumer(consumer, params); err != nil {
		return nil, err
	}

	return r, nil
}

func createMetricsReceiver(
	ctx context.Context,
	params receiver.Settings,
	rConf component.Config,
	consumer consumer.Metrics,
) (receiver.Metrics, error) {
	cfg := rConf.(*Config)

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	var err error
	r := receivers.GetOrAdd(cfg, func() component.Component {
		dd, createErr := newVercelReceiver(params, cfg)
		err = createErr
		return dd
	})

	if err != nil {
		return nil, err
	}

	if err := r.Unwrap().(*vercelReceiver).RegisterMetricsConsumer(consumer, params); err != nil {
		return nil, err
	}

	return r, nil
}

func createDefaultConfig() component.Config {
	return &Config{
		Endpoint:      ":8080",
		Secret:        "", // Default secret (empty means no auth by default)
		Logs:          SignalConfig{},
		Traces:        SignalConfig{},
		SpeedInsights: SignalConfig{},
		WebAnalytics:  SignalConfig{},
	}
}
