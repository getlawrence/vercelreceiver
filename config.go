package vercelreceiver

import (
	"fmt"
	"net"
)

type Config struct {
	Logs          LogsConfig          `mapstructure:"logs"`
	Traces        TracesConfig        `mapstructure:"traces"`
	SpeedInsights SpeedInsightsConfig `mapstructure:"speed_insights"`
	WebAnalytics  WebAnalyticsConfig  `mapstructure:"web_analytics"`
}

// Validate validates the configuration
func (cfg *Config) Validate() error {
	if err := cfg.Logs.Validate(); err != nil {
		return fmt.Errorf("logs config validation failed: %w", err)
	}
	if err := cfg.Traces.Validate(); err != nil {
		return fmt.Errorf("traces config validation failed: %w", err)
	}
	if err := cfg.SpeedInsights.Validate(); err != nil {
		return fmt.Errorf("speed_insights config validation failed: %w", err)
	}
	if err := cfg.WebAnalytics.Validate(); err != nil {
		return fmt.Errorf("web_analytics config validation failed: %w", err)
	}
	return nil
}

// LogsConfig defines configuration for log drains
type LogsConfig struct {
	Endpoint string `mapstructure:"endpoint"`
	Secret   string `mapstructure:"secret"`
}

// Validate validates the logs configuration
func (cfg *LogsConfig) Validate() error {
	if cfg.Endpoint != "" {
		if err := validateEndpoint(cfg.Endpoint); err != nil {
			return fmt.Errorf("invalid logs endpoint: %w", err)
		}
	}
	return nil
}

// TracesConfig defines configuration for trace drains
type TracesConfig struct {
	Endpoint string `mapstructure:"endpoint"`
	Secret   string `mapstructure:"secret"`
}

// Validate validates the traces configuration
func (cfg *TracesConfig) Validate() error {
	if cfg.Endpoint != "" {
		if err := validateEndpoint(cfg.Endpoint); err != nil {
			return fmt.Errorf("invalid traces endpoint: %w", err)
		}
	}
	return nil
}

// SpeedInsightsConfig defines configuration for speed insights drains
type SpeedInsightsConfig struct {
	Endpoint string `mapstructure:"endpoint"`
	Secret   string `mapstructure:"secret"`
}

// Validate validates the speed insights configuration
func (cfg *SpeedInsightsConfig) Validate() error {
	if cfg.Endpoint != "" {
		if err := validateEndpoint(cfg.Endpoint); err != nil {
			return fmt.Errorf("invalid speed_insights endpoint: %w", err)
		}
	}
	return nil
}

// WebAnalyticsConfig defines configuration for web analytics drains
type WebAnalyticsConfig struct {
	Endpoint string `mapstructure:"endpoint"`
	Secret   string `mapstructure:"secret"`
}

// Validate validates the web analytics configuration
func (cfg *WebAnalyticsConfig) Validate() error {
	if cfg.Endpoint != "" {
		if err := validateEndpoint(cfg.Endpoint); err != nil {
			return fmt.Errorf("invalid web_analytics endpoint: %w", err)
		}
	}
	return nil
}

// validateEndpoint validates that the endpoint is in the correct host:port format
func validateEndpoint(endpoint string) error {
	if endpoint == "" {
		return fmt.Errorf("endpoint cannot be empty")
	}

	// Check if it's a valid host:port format
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return fmt.Errorf("failed to split endpoint into 'host:port' pair: %w", err)
	}

	if host == "" {
		return fmt.Errorf("host cannot be empty")
	}

	if port == "" {
		return fmt.Errorf("port cannot be empty")
	}

	// Validate that the port is a valid number
	if _, err := net.LookupPort("tcp", port); err != nil {
		return fmt.Errorf("invalid port '%s': %w", port, err)
	}

	return nil
}
