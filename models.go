package vercelreceiver

// vercelLog represents a Vercel log entry
type vercelLog struct {
	ID              string       `json:"id"`
	DeploymentID    string       `json:"deploymentId"`
	Source          string       `json:"source"`
	Host            string       `json:"host"`
	Timestamp       int64        `json:"timestamp"`
	ProjectID       string       `json:"projectId"`
	Level           string       `json:"level"`
	Message         string       `json:"message"`
	BuildID         string       `json:"buildId,omitempty"`
	Entrypoint      string       `json:"entrypoint,omitempty"`
	Destination     string       `json:"destination,omitempty"`
	Path            string       `json:"path,omitempty"`
	Type            string       `json:"type,omitempty"`
	StatusCode      int          `json:"statusCode,omitempty"`
	RequestID       string       `json:"requestId,omitempty"`
	Environment     string       `json:"environment,omitempty"`
	Branch          string       `json:"branch,omitempty"`
	JA3Digest       string       `json:"ja3Digest,omitempty"`
	JA4Digest       string       `json:"ja4Digest,omitempty"`
	EdgeType        string       `json:"edgeType,omitempty"`
	ProjectName     string       `json:"projectName,omitempty"`
	ExecutionRegion string       `json:"executionRegion,omitempty"`
	TraceID         string       `json:"traceId,omitempty"`
	SpanID          string       `json:"spanId,omitempty"`
	TraceIDAlt      string       `json:"trace.id,omitempty"`
	SpanIDAlt       string       `json:"span.id,omitempty"`
	Proxy           *vercelProxy `json:"proxy,omitempty"`
}

// vercelProxy represents proxy information in a Vercel log entry
type vercelProxy struct {
	Timestamp        int64    `json:"timestamp"`
	Method           string   `json:"method"`
	Host             string   `json:"host"`
	Path             string   `json:"path"`
	UserAgent        []string `json:"userAgent"`
	Region           string   `json:"region"`
	Referer          string   `json:"referer,omitempty"`
	StatusCode       int      `json:"statusCode,omitempty"`
	ClientIP         string   `json:"clientIp,omitempty"`
	Scheme           string   `json:"scheme,omitempty"`
	ResponseByteSize int64    `json:"responseByteSize,omitempty"`
	CacheID          string   `json:"cacheId,omitempty"`
	PathType         string   `json:"pathType,omitempty"`
	PathTypeVariant  string   `json:"pathTypeVariant,omitempty"`
	VercelID         string   `json:"vercelId,omitempty"`
	VercelCache      string   `json:"vercelCache,omitempty"`
	LambdaRegion     string   `json:"lambdaRegion,omitempty"`
	WAFAction        string   `json:"wafAction,omitempty"`
	WAFRuleID        string   `json:"wafRuleId,omitempty"`
}

// speedInsight represents a Vercel Speed Insights metric entry
type speedInsight struct {
	Schema               string  `json:"schema"`
	Timestamp            string  `json:"timestamp"`
	ProjectID            string  `json:"projectId"`
	OwnerID              string  `json:"ownerId"`
	DeviceID             int64   `json:"deviceId"`
	MetricType           string  `json:"metricType"`
	Value                float64 `json:"value"`
	Origin               string  `json:"origin"`
	Path                 string  `json:"path"`
	Route                string  `json:"route,omitempty"`
	Country              string  `json:"country,omitempty"`
	Region               string  `json:"region,omitempty"`
	City                 string  `json:"city,omitempty"`
	OSName               string  `json:"osName,omitempty"`
	OSVersion            string  `json:"osVersion,omitempty"`
	ClientName           string  `json:"clientName,omitempty"`
	ClientType           string  `json:"clientType,omitempty"`
	ClientVersion        string  `json:"clientVersion,omitempty"`
	DeviceType           string  `json:"deviceType,omitempty"`
	DeviceBrand          string  `json:"deviceBrand,omitempty"`
	ConnectionSpeed      string  `json:"connectionSpeed,omitempty"`
	BrowserEngine        string  `json:"browserEngine,omitempty"`
	BrowserEngineVersion string  `json:"browserEngineVersion,omitempty"`
	ScriptVersion        string  `json:"scriptVersion,omitempty"`
	SDKVersion           string  `json:"sdkVersion,omitempty"`
	SDKName              string  `json:"sdkName,omitempty"`
	VercelEnvironment    string  `json:"vercelEnvironment,omitempty"`
	VercelURL            string  `json:"vercelUrl,omitempty"`
	DeploymentID         string  `json:"deploymentId,omitempty"`
	Attribution          string  `json:"attribution,omitempty"`
}

// webAnalyticsEvent represents a Vercel Web Analytics event
type webAnalyticsEvent struct {
	Schema               string `json:"schema"`
	EventType            string `json:"eventType"`
	EventName            string `json:"eventName,omitempty"`
	EventData            string `json:"eventData,omitempty"`
	Timestamp            int64  `json:"timestamp"`
	ProjectID            string `json:"projectId"`
	OwnerID              string `json:"ownerId"`
	DataSourceName       string `json:"dataSourceName"`
	SessionID            int64  `json:"sessionId"`
	DeviceID             int64  `json:"deviceId"`
	Origin               string `json:"origin"`
	Path                 string `json:"path"`
	Referrer             string `json:"referrer,omitempty"`
	QueryParams          string `json:"queryParams,omitempty"`
	Route                string `json:"route,omitempty"`
	Country              string `json:"country,omitempty"`
	Region               string `json:"region,omitempty"`
	City                 string `json:"city,omitempty"`
	OSName               string `json:"osName,omitempty"`
	OSVersion            string `json:"osVersion,omitempty"`
	ClientName           string `json:"clientName,omitempty"`
	ClientType           string `json:"clientType,omitempty"`
	ClientVersion        string `json:"clientVersion,omitempty"`
	DeviceType           string `json:"deviceType,omitempty"`
	DeviceBrand          string `json:"deviceBrand,omitempty"`
	DeviceModel          string `json:"deviceModel,omitempty"`
	BrowserEngine        string `json:"browserEngine,omitempty"`
	BrowserEngineVersion string `json:"browserEngineVersion,omitempty"`
	SDKVersion           string `json:"sdkVersion,omitempty"`
	SDKName              string `json:"sdkName,omitempty"`
	SDKVersionFull       string `json:"sdkVersionFull,omitempty"`
	VercelEnvironment    string `json:"vercelEnvironment,omitempty"`
	VercelURL            string `json:"vercelUrl,omitempty"`
	Flags                string `json:"flags,omitempty"`
	Deployment           string `json:"deployment,omitempty"`
}
