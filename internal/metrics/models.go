package metrics

import (
	"fmt"
	"strings"
	"time"
)

// MetricSeries represents a single time series returned from Prometheus.
type MetricSeries struct {
	MetricName string            `json:"metric_name"`
	Labels     map[string]string `json:"labels"`
	DataPoints []DataPoint       `json:"data_points"`
}

// DataPoint is a single timestamp-value pair.
type DataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

// Summary produces a human-readable trend summary for LLM prompts.
func (s MetricSeries) Summary() string {
	if len(s.DataPoints) == 0 {
		return fmt.Sprintf("%s: no data", s.MetricName)
	}
	first := s.DataPoints[0].Value
	last := s.DataPoints[len(s.DataPoints)-1].Value
	trend := "stable"
	diff := last - first
	if diff > first*0.1 {
		trend = "rising"
	}
	if diff < -first*0.1 {
		trend = "falling"
	}
	// Check for spikes
	var max float64
	for _, dp := range s.DataPoints {
		if dp.Value > max {
			max = dp.Value
		}
	}
	if max > last*1.5 && max > first*1.5 {
		trend = "spike"
	}

	labels := make([]string, 0, len(s.Labels))
	for k, v := range s.Labels {
		labels = append(labels, fmt.Sprintf("%s=%q", k, v))
	}
	return fmt.Sprintf("%s{%s}: %.4f -> %.4f (%s)", s.MetricName, strings.Join(labels, ","), first, last, trend)
}
