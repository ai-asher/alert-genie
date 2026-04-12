package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Analyzer produces an AnalysisResult from an AnalysisRequest by calling an LLM.
type Analyzer interface {
	Analyze(ctx context.Context, req AnalysisRequest) (*AnalysisResult, error)
}

// claudeAnalyzer implements Analyzer using the Anthropic Messages API.
type claudeAnalyzer struct {
	baseURL      string
	apiKey       string
	model        string
	maxTokens    int
	temperature  float64
	timeout      time.Duration
	maxRetries   int
	retryBackoff time.Duration
	client       *http.Client
	prompt       *PromptBuilder
}

// NewClaudeAnalyzer creates an Analyzer backed by the Anthropic Claude Messages API.
func NewClaudeAnalyzer(
	baseURL, apiKey, model string,
	maxTokens int,
	temperature float64,
	timeout time.Duration,
	maxRetries int,
	retryBackoff time.Duration,
) Analyzer {
	return &claudeAnalyzer{
		baseURL:      strings.TrimRight(baseURL, "/"),
		apiKey:       apiKey,
		model:        model,
		maxTokens:    maxTokens,
		temperature:  temperature,
		timeout:      timeout,
		maxRetries:   maxRetries,
		retryBackoff: retryBackoff,
		client:       &http.Client{Timeout: timeout},
		prompt:       &PromptBuilder{},
	}
}

// claudeRequest is the request body for POST /v1/messages.
type claudeRequest struct {
	Model       string          `json:"model"`
	MaxTokens   int             `json:"max_tokens"`
	System      string          `json:"system,omitempty"`
	Messages    []claudeMessage `json:"messages"`
	Temperature *float64        `json:"temperature,omitempty"`
}

type claudeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// claudeResponse is the response from POST /v1/messages.
type claudeResponse struct {
	ID      string               `json:"id"`
	Type    string               `json:"type"`
	Role    string               `json:"role"`
	Content []claudeContentBlock `json:"content"`
	Model   string               `json:"model"`
	Usage   claudeUsage          `json:"usage"`
}

type claudeContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type claudeUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// claudeErrorResponse represents an error from the Claude API.
type claudeErrorResponse struct {
	Type  string      `json:"type"`
	Error claudeError `json:"error"`
}

type claudeError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

func (ca *claudeAnalyzer) Analyze(ctx context.Context, req AnalysisRequest) (*AnalysisResult, error) {
	systemPrompt, userMessage, err := ca.prompt.Build(req)
	if err != nil {
		return nil, fmt.Errorf("build prompt: %w", err)
	}

	slog.Info("sending analysis request to Claude",
		"alert", req.AlertName,
		"model", ca.model,
		"mode", req.Mode,
	)

	var resp *claudeResponse
	var lastErr error

	for attempt := 0; attempt <= ca.maxRetries; attempt++ {
		if attempt > 0 {
			slog.Warn("retrying Claude API call",
				"attempt", attempt,
				"max_retries", ca.maxRetries,
				"backoff", ca.retryBackoff*time.Duration(attempt),
			)
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("context cancelled during retry: %w", ctx.Err())
			case <-time.After(ca.retryBackoff * time.Duration(attempt)):
			}
		}

		resp, lastErr = ca.callAPI(ctx, systemPrompt, userMessage)
		if lastErr == nil {
			break
		}

		slog.Error("Claude API call failed",
			"attempt", attempt,
			"error", lastErr,
		)
	}

	if lastErr != nil {
		return nil, fmt.Errorf("claude API failed after %d retries: %w", ca.maxRetries, lastErr)
	}

	// Extract text content from the response.
	text := extractText(resp)
	if text == "" {
		return nil, fmt.Errorf("empty text response from Claude")
	}

	slog.Debug("received Claude response", "text_length", len(text))

	// Parse the JSON response into AnalysisResult.
	result, err := parseAnalysisResult(text)
	if err != nil {
		return nil, fmt.Errorf("parse analysis result: %w", err)
	}

	// Fill in metadata from the API response.
	result.AnalyzedAt = time.Now()
	result.ModelUsed = resp.Model
	result.TokensUsed = TokenUsage{
		InputTokens:  resp.Usage.InputTokens,
		OutputTokens: resp.Usage.OutputTokens,
	}

	return result, nil
}

func (ca *claudeAnalyzer) callAPI(ctx context.Context, systemPrompt, userMessage string) (*claudeResponse, error) {
	temp := ca.temperature
	reqBody := claudeRequest{
		Model:     ca.model,
		MaxTokens: ca.maxTokens,
		System:    systemPrompt,
		Messages: []claudeMessage{
			{Role: "user", Content: userMessage},
		},
		Temperature: &temp,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request body: %w", err)
	}

	endpoint := ca.baseURL + "/v1/messages"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", ca.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	httpResp, err := ca.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("execute HTTP request: %w", err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		var apiErr claudeErrorResponse
		if jsonErr := json.Unmarshal(respBody, &apiErr); jsonErr == nil && apiErr.Error.Message != "" {
			return nil, fmt.Errorf("claude API error (HTTP %d, %s): %s",
				httpResp.StatusCode, apiErr.Error.Type, apiErr.Error.Message)
		}
		return nil, fmt.Errorf("claude API returned HTTP %d: %s", httpResp.StatusCode, string(respBody))
	}

	var resp claudeResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &resp, nil
}

// extractText concatenates all text blocks from the Claude response.
func extractText(resp *claudeResponse) string {
	var parts []string
	for _, block := range resp.Content {
		if block.Type == "text" {
			parts = append(parts, block.Text)
		}
	}
	return strings.Join(parts, "")
}

// parseAnalysisResult extracts a JSON AnalysisResult from the LLM text output.
// It handles cases where the model wraps JSON in markdown code fences.
func parseAnalysisResult(text string) (*AnalysisResult, error) {
	// Strip markdown code fences if present.
	cleaned := strings.TrimSpace(text)
	if strings.HasPrefix(cleaned, "```") {
		// Remove opening fence (possibly with language tag).
		if idx := strings.Index(cleaned, "\n"); idx != -1 {
			cleaned = cleaned[idx+1:]
		}
		// Remove closing fence.
		if idx := strings.LastIndex(cleaned, "```"); idx != -1 {
			cleaned = cleaned[:idx]
		}
		cleaned = strings.TrimSpace(cleaned)
	}

	var result AnalysisResult
	if err := json.Unmarshal([]byte(cleaned), &result); err != nil {
		return nil, fmt.Errorf("unmarshal JSON from LLM output: %w (raw text starts with: %.100s)", err, cleaned)
	}
	return &result, nil
}
