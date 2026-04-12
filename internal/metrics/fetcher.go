package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Fetcher abstracts metric data retrieval.
type Fetcher interface {
	// QueryRange executes a PromQL range query ending at `end` over the given window.
	QueryRange(ctx context.Context, query string, end time.Time, window time.Duration) ([]MetricSeries, error)
}

// promFetcher implements Fetcher using the Prometheus HTTP API.
type promFetcher struct {
	address string
	client  *http.Client
}

// NewPrometheusFetcher creates a Fetcher backed by a Prometheus server.
func NewPrometheusFetcher(address string, timeout time.Duration) Fetcher {
	return &promFetcher{
		address: address,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// promResponse models the top-level Prometheus API JSON envelope.
type promResponse struct {
	Status    string   `json:"status"`
	Data      promData `json:"data"`
	ErrorType string   `json:"errorType,omitempty"`
	Error     string   `json:"error,omitempty"`
}

// promData models the "data" field inside a Prometheus API response.
type promData struct {
	ResultType string             `json:"resultType"`
	Result     []promMatrixResult `json:"result"`
}

// promMatrixResult is a single series in a matrix response.
type promMatrixResult struct {
	Metric map[string]string `json:"metric"`
	Values []promValue       `json:"values"`
}

// promValue is a [timestamp, value] pair from the Prometheus matrix result.
// Prometheus returns each value as a two-element JSON array: [unix_seconds, "string_value"].
type promValue [2]json.RawMessage

func (pf *promFetcher) QueryRange(ctx context.Context, query string, end time.Time, window time.Duration) ([]MetricSeries, error) {
	start := end.Add(-window)

	// Calculate a reasonable step: aim for ~120 data points.
	step := window / 120
	if step < time.Second {
		step = time.Second
	}

	u, err := url.Parse(pf.address)
	if err != nil {
		return nil, fmt.Errorf("parse prometheus address: %w", err)
	}
	u.Path = "/api/v1/query_range"

	params := url.Values{}
	params.Set("query", query)
	params.Set("start", strconv.FormatFloat(float64(start.Unix()), 'f', 0, 64))
	params.Set("end", strconv.FormatFloat(float64(end.Unix()), 'f', 0, 64))
	params.Set("step", fmt.Sprintf("%ds", int(step.Seconds())))
	u.RawQuery = params.Encode()

	slog.Debug("querying prometheus", "url", u.String(), "query", query)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := pf.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute prometheus query: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read prometheus response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("prometheus returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var promResp promResponse
	if err := json.Unmarshal(body, &promResp); err != nil {
		return nil, fmt.Errorf("decode prometheus response: %w", err)
	}

	if promResp.Status != "success" {
		return nil, fmt.Errorf("prometheus query error (%s): %s", promResp.ErrorType, promResp.Error)
	}

	if promResp.Data.ResultType != "matrix" {
		return nil, fmt.Errorf("unexpected result type %q, expected matrix", promResp.Data.ResultType)
	}

	return parseMatrixResult(promResp.Data.Result)
}

func parseMatrixResult(results []promMatrixResult) ([]MetricSeries, error) {
	series := make([]MetricSeries, 0, len(results))

	for _, r := range results {
		ms := MetricSeries{
			MetricName: r.Metric["__name__"],
			Labels:     make(map[string]string, len(r.Metric)),
			DataPoints: make([]DataPoint, 0, len(r.Values)),
		}
		for k, v := range r.Metric {
			if k != "__name__" {
				ms.Labels[k] = v
			}
		}

		for _, v := range r.Values {
			dp, err := parsePromValue(v)
			if err != nil {
				slog.Warn("skipping malformed data point", "error", err)
				continue
			}
			ms.DataPoints = append(ms.DataPoints, dp)
		}

		series = append(series, ms)
	}

	return series, nil
}

func parsePromValue(pv promValue) (DataPoint, error) {
	// pv[0] is the Unix timestamp (number), pv[1] is the value (string).
	var ts float64
	if err := json.Unmarshal(pv[0], &ts); err != nil {
		return DataPoint{}, fmt.Errorf("parse timestamp: %w", err)
	}

	var valStr string
	if err := json.Unmarshal(pv[1], &valStr); err != nil {
		return DataPoint{}, fmt.Errorf("parse value string: %w", err)
	}

	val, err := strconv.ParseFloat(valStr, 64)
	if err != nil {
		return DataPoint{}, fmt.Errorf("parse float value %q: %w", valStr, err)
	}

	return DataPoint{
		Timestamp: time.Unix(int64(ts), int64((ts-float64(int64(ts)))*1e9)),
		Value:     val,
	}, nil
}
