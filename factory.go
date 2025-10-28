package vercelreceiver

import (
	"context"
	"sync"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
)

// SharedComponents a map that keeps reference of all created instances for a given configuration,
// and ensures that the shared state is started and stopped only once.
type SharedComponents struct {
	comps map[any]*SharedComponent
	mu    sync.Mutex
}

// NewSharedComponents returns a new empty SharedComponents.
func NewSharedComponents() *SharedComponents {
	return &SharedComponents{
		comps: make(map[any]*SharedComponent),
	}
}

// GetOrAdd returns the already created instance if exists, otherwise creates a new instance
// and adds it to the map of references.
func (scs *SharedComponents) GetOrAdd(key any, create func() component.Component) *SharedComponent {
	scs.mu.Lock()
	defer scs.mu.Unlock()

	if c, ok := scs.comps[key]; ok {
		return c
	}

	newComp := &SharedComponent{
		Component: create(),
		removeFunc: func() {
			scs.mu.Lock()
			defer scs.mu.Unlock()
			delete(scs.comps, key)
		},
	}

	scs.comps[key] = newComp
	return newComp
}

// SharedComponent ensures that the wrapped component is started and stopped only once.
// When stopped it is removed from the SharedComponents map.
type SharedComponent struct {
	component.Component
	startOnce  sync.Once
	stopOnce   sync.Once
	removeFunc func()
}

// Unwrap returns the original component.
func (r *SharedComponent) Unwrap() component.Component {
	return r.Component
}

// Start implements component.Component.
func (r *SharedComponent) Start(ctx context.Context, host component.Host) error {
	var err error
	r.startOnce.Do(func() {
		err = r.Component.Start(ctx, host)
	})
	return err
}

// Shutdown implements component.Component.
func (r *SharedComponent) Shutdown(ctx context.Context) error {
	var err error
	r.stopOnce.Do(func() {
		err = r.Component.Shutdown(ctx)
		r.removeFunc()
	})
	return err
}

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
