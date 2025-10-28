package vercelreceiver

import (
	"context"
	"sync"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/receiverhelper"
)

// sharedReceivers manages shared receiver instances across signal types.
// This is necessary because the receiver.Factory is asked for trace, log, and metric receivers separately
// when it calls createLogsReceiver(), createTracesReceiver(), and createMetricsReceiver() but they must not
// create separate objects - they must use one vercelReceiver object per configuration.
type sharedReceivers struct {
	mu        sync.Mutex
	receivers map[component.ID]*vercelReceiver
}

func newSharedReceivers() *sharedReceivers {
	return &sharedReceivers{
		receivers: make(map[component.ID]*vercelReceiver),
	}
}

// GetOrAdd returns an existing receiver or creates a new one using the provided factory function.
func (s *sharedReceivers) GetOrAdd(id component.ID, create func() *vercelReceiver) *vercelReceiver {
	s.mu.Lock()
	defer s.mu.Unlock()

	if r, exists := s.receivers[id]; exists {
		return r
	}

	r := create()
	s.receivers[id] = r
	return r
}

var receivers = newSharedReceivers()

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
	_ context.Context,
	params receiver.Settings,
	rConf component.Config,
	consumer consumer.Logs,
) (receiver.Logs, error) {
	cfg := rConf.(*Config)
	
	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	
	r := getOrCreateReceiver(params, cfg)
	r.logsConsumer = consumer

	// Create logs obsrecv if not already created
	if r.logsObsrecv == nil {
		obsrecv, err := receiverhelper.NewObsReport(receiverhelper.ObsReportSettings{
			ReceiverID:             params.ID,
			Transport:              "http",
			ReceiverCreateSettings: params,
		})
		if err != nil {
			return nil, err
		}
		r.logsObsrecv = obsrecv
	}

	// Update server handlers
	r.server.logsHandler = r.handleLogs
	r.server.analyticsHandler = r.handleWebAnalytics

	return r, nil
}

func createTracesReceiver(
	_ context.Context,
	params receiver.Settings,
	rConf component.Config,
	consumer consumer.Traces,
) (receiver.Traces, error) {
	cfg := rConf.(*Config)
	
	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	
	r := getOrCreateReceiver(params, cfg)
	r.tracesConsumer = consumer

	// Create traces obsrecv if not already created
	if r.tracesObsrecv == nil {
		obsrecv, err := receiverhelper.NewObsReport(receiverhelper.ObsReportSettings{
			ReceiverID:             params.ID,
			Transport:              "http",
			ReceiverCreateSettings: params,
		})
		if err != nil {
			return nil, err
		}
		r.tracesObsrecv = obsrecv
	}

	// Update server handlers
	r.server.tracesHandler = r.handleTraces

	return r, nil
}

func createMetricsReceiver(
	_ context.Context,
	params receiver.Settings,
	rConf component.Config,
	consumer consumer.Metrics,
) (receiver.Metrics, error) {
	cfg := rConf.(*Config)
	
	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	
	r := getOrCreateReceiver(params, cfg)
	r.metricsConsumer = consumer

	// Create metrics obsrecv if not already created
	if r.metricsObsrecv == nil {
		obsrecv, err := receiverhelper.NewObsReport(receiverhelper.ObsReportSettings{
			ReceiverID:             params.ID,
			Transport:              "http",
			ReceiverCreateSettings: params,
		})
		if err != nil {
			return nil, err
		}
		r.metricsObsrecv = obsrecv
	}

	// Update server handlers
	r.server.speedInsightsHandler = r.handleSpeedInsights

	return r, nil
}

// getOrCreateReceiver returns an existing receiver or creates a new one using GetOrAdd
func getOrCreateReceiver(params receiver.Settings, cfg *Config) *vercelReceiver {
	return receivers.GetOrAdd(params.ID, func() *vercelReceiver {
		return &vercelReceiver{
			logger: params.Logger,
			cfg:    cfg,
			wg:     &sync.WaitGroup{},
			server: newHTTPServer(cfg, params.Logger),
		}
	})
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
