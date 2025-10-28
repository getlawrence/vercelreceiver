package vercelreceiver

type Config struct {
	Logs          LogsConfig          `mapstructure:"logs"`
	Traces        TracesConfig        `mapstructure:"traces"`
	SpeedInsights SpeedInsightsConfig `mapstructure:"speed_insights"`
	WebAnalytics  WebAnalyticsConfig  `mapstructure:"web_analytics"`
}

// LogsConfig defines configuration for log drains
type LogsConfig struct {
	Endpoint string `mapstructure:"endpoint"`
	Secret   string `mapstructure:"secret"`
}

// TracesConfig defines configuration for trace drains
type TracesConfig struct {
	Endpoint string `mapstructure:"endpoint"`
	Secret   string `mapstructure:"secret"`
}

// SpeedInsightsConfig defines configuration for speed insights drains
type SpeedInsightsConfig struct {
	Endpoint string `mapstructure:"endpoint"`
	Secret   string `mapstructure:"secret"`
}

// WebAnalyticsConfig defines configuration for web analytics drains
type WebAnalyticsConfig struct {
	Endpoint string `mapstructure:"endpoint"`
	Secret   string `mapstructure:"secret"`
}
