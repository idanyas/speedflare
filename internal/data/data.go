package data

type Location struct {
	IATA   string  `json:"iata"`
	City   string  `json:"city"`
	CCA2   string  `json:"cca2"`
	Region string  `json:"region"`
	Lat    float64 `json:"lat"`
	Lon    float64 `json:"lon"`
}

type TestResult struct {
	IP       string `json:"ip"`
	Server   Server `json:"server"`
	Latency  Stats  `json:"latency"`
	Download Speed  `json:"download"`
	Upload   Speed  `json:"upload"`
}

type Server struct {
	IATA     string  `json:"iata"`
	City     string  `json:"city"`
	Country  string  `json:"country"`
	Lat      float64 `json:"lat"`
	Lon      float64 `json:"lon"`
	IP       string  `json:"ip,omitempty"`       // The Anycast IP used
	Distance float64 `json:"distance,omitempty"` // Distance from user in km
}

type Stats struct {
	Value  float64 `json:"value_ms"`
	Jitter float64 `json:"jitter_ms"`
	Min    float64 `json:"min_ms"`
	Max    float64 `json:"max_ms"`
}

type Speed struct {
	Mbps   float64 `json:"mbps"`
	DataMB float64 `json:"data_mb"`
}

type LatencyResult struct {
	Avg    float64
	Jitter float64
	Min    float64
	Max    float64
}
