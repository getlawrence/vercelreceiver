package vercelreceiver

import (
	"go.opentelemetry.io/collector/component"
)

const (
	TypeStr   = "vercel"
	stability = component.StabilityLevelBeta
)

var (
	LogsStability    = component.StabilityLevelBeta
	TracesStability  = component.StabilityLevelBeta
	MetricsStability = component.StabilityLevelBeta
)

var Type = component.MustNewType(TypeStr)
