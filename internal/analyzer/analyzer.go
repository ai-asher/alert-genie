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
//
// Chat extends the analyzer with multi-turn conversation support: given the
// original analysis, prior conversation history, and a new user message, it
// returns either a plain text reply or a revised healing plan.
type Analyzer interface {
	Analyze(ctx context.Context, req AnalysisRequest) (*AnalysisResult, error)
	Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error)
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

		resp, lastErr = ca.callAPI(ctx, systemPrompt, []claudeMessage{
			{Role: "user", Content: userMessage},
		})
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

// Chat handles a multi-turn follow-up conversation about a previously
// analyzed alert. It returns either a plain text reply or a revised healing
// plan, depending on the user's intent.
func (ca *claudeAnalyzer) Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	systemPrompt, latestUserMessage, err := ca.prompt.BuildChat(req)
	if err != nil {
		return nil, fmt.Errorf("build chat prompt: %w", err)
	}

	// Build the messages slice: prior history (chronological, oldest first),
	// then the current user message as the final entry.
	messages := make([]claudeMessage, 0, len(req.History)+1)
	for _, m := range req.History {
		messages = append(messages, claudeMessage{Role: m.Role, Content: m.Content})
	}
	messages = append(messages, claudeMessage{Role: "user", Content: latestUserMessage})

	slog.Info("sending chat request to Claude",
		"model", ca.model,
		"history_turns", len(req.History),
		"user_name", req.UserName,
	)

	var resp *claudeResponse
	var lastErr error

	for attempt := 0; attempt <= ca.maxRetries; attempt++ {
		if attempt > 0 {
			slog.Warn("retrying Claude chat API call",
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

		resp, lastErr = ca.callAPI(ctx, systemPrompt, messages)
		if lastErr == nil {
			break
		}

		slog.Error("Claude chat API call failed",
			"attempt", attempt,
			"error", lastErr,
		)
	}

	if lastErr != nil {
		return nil, fmt.Errorf("claude chat API failed after %d retries: %w", ca.maxRetries, lastErr)
	}

	text := extractText(resp)
	if text == "" {
		return nil, fmt.Errorf("empty text response from Claude chat")
	}

	slog.Debug("received Claude chat response", "text_length", len(text))

	chatResp, err := parseChatResponse(text)
	if err != nil {
		return nil, fmt.Errorf("parse chat response: %w", err)
	}

	// Fill in metadata from the API response.
	chatResp.AnalyzedAt = time.Now()
	chatResp.ModelUsed = resp.Model
	chatResp.TokensUsed = TokenUsage{
		InputTokens:  resp.Usage.InputTokens,
		OutputTokens: resp.Usage.OutputTokens,
	}

	return chatResp, nil
}

func (ca *claudeAnalyzer) callAPI(ctx context.Context, systemPrompt string, messages []claudeMessage) (*claudeResponse, error) {
	temp := ca.temperature
	reqBody := claudeRequest{
		Model:       ca.model,
		MaxTokens:   ca.maxTokens,
		System:      systemPrompt,
		Messages:    messages,
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
	cleaned := stripCodeFences(text)
	var result AnalysisResult
	if err := json.Unmarshal([]byte(cleaned), &result); err != nil {
		return nil, fmt.Errorf("unmarshal JSON from LLM output: %w (raw text starts with: %.100s)", err, cleaned)
	}
	return &result, nil
}

// parseChatResponse extracts a JSON ChatResponse from the LLM text output,
// tolerating markdown code fences just like parseAnalysisResult.
func parseChatResponse(text string) (*ChatResponse, error) {
	cleaned := stripCodeFences(text)
	var result ChatResponse
	if err := json.Unmarshal([]byte(cleaned), &result); err != nil {
		return nil, fmt.Errorf("unmarshal chat JSON from LLM output: %w (raw text starts with: %.100s)", err, cleaned)
	}
	return &result, nil
}

// stripCodeFences removes a single surrounding markdown code fence (with an
// optional language tag) from the text, if present.
func stripCodeFences(text string) string {
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
	return cleaned
}
