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
//
// RankIncidents is a lightweight relevance-ranking call used by the historical
// retriever. It scores past incidents against a current alert and returns
// the top K, with reasons. Implemented as a separate small prompt to keep
// per-alert cost bounded.
type Analyzer interface {
	Analyze(ctx context.Context, req AnalysisRequest) (*AnalysisResult, error)
	Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error)
	RankIncidents(ctx context.Context, req RankRequest) (*RankResponse, error)
}

// RankRequest carries everything needed for the ranker call.
type RankRequest struct {
	// CurrentAlert is the new alert needing context.
	CurrentAlertJSON string
	// CandidatesJSON is a JSON array of candidate incidents (compact form).
	CandidatesJSON string
	// TopK is how many incidents to return.
	TopK int
}

// RankResponse is the ranker's structured output.
type RankResponse struct {
	Ranked     []RankedItem `json:"ranked"`
	ModelUsed  string       `json:"model_used"`
	TokensUsed TokenUsage   `json:"tokens_used"`
}

// RankedItem is a single ranked incident reference.
type RankedItem struct {
	AlertID         string  `json:"alert_id"`
	RelevanceScore  float64 `json:"relevance_score"`  // 0.0-1.0
	RelevanceReason string  `json:"relevance_reason"` // 1-2 sentence
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

// RankIncidents asks Claude to score historical incident relevance to the
// current alert. The prompt is intentionally tiny and constrained to JSON
// output to keep cost bounded.
func (ca *claudeAnalyzer) RankIncidents(ctx context.Context, req RankRequest) (*RankResponse, error) {
	if req.TopK <= 0 {
		req.TopK = 3
	}

	systemPrompt := fmt.Sprintf(`You are an SRE assistant that ranks historical incidents by relevance to a new alert. You will receive:

- The CURRENT alert (subject of the new analysis).
- A JSON array of CANDIDATE past incidents.

Your job: pick the %d candidates MOST relevant to the current alert. Relevance is highest when:

1. Same alertname OR clearly the same kind of issue (e.g. "high memory" vs "OOM").
2. Same affected service / component (look at labels: service, job, namespace, instance).
3. The candidate's resolution would plausibly apply to the current alert.

Penalize candidates that are clearly different problems even if alertname matches (e.g. memory pressure on a different unrelated service).

OUTPUT: a single JSON object, no markdown, no prose. Schema:

{
  "ranked": [
    {
      "alert_id": "<exact alert_id from candidates>",
      "relevance_score": 0.0-1.0,
      "relevance_reason": "<one sentence explaining why this is relevant>"
    }
  ]
}

Only include candidates with relevance_score >= 0.4. If nothing is relevant, return {"ranked": []}.

CRITICAL: alert_id must be copied EXACTLY from the candidate list. Never fabricate IDs. Order results by relevance_score descending.`, req.TopK)

	userMessage := fmt.Sprintf("CURRENT ALERT:\n%s\n\nCANDIDATES (JSON array):\n%s",
		req.CurrentAlertJSON, req.CandidatesJSON)

	resp, err := ca.callAPI(ctx, systemPrompt, []claudeMessage{
		{Role: "user", Content: userMessage},
	})
	if err != nil {
		return nil, fmt.Errorf("rank API call: %w", err)
	}

	text := extractText(resp)
	cleaned := stripCodeFences(text)
	if extracted := extractFirstJSONObject(cleaned); extracted != "" {
		cleaned = extracted
	}

	var rr RankResponse
	if err := json.Unmarshal([]byte(cleaned), &rr); err != nil {
		return nil, fmt.Errorf("parse rank JSON: %w (raw: %.200s)", err, text)
	}

	rr.ModelUsed = resp.Model
	rr.TokensUsed = TokenUsage{
		InputTokens:  resp.Usage.InputTokens,
		OutputTokens: resp.Usage.OutputTokens,
	}
	return &rr, nil
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
// tolerating markdown code fences. On parse failure, returns a best-effort
// text response carrying the raw LLM output so the user still gets SOMETHING
// rather than an opaque error. This matters because a malformed JSON would
// otherwise turn a "the LLM rambled instead of returning JSON" into an outage
// from the user's perspective.
func parseChatResponse(text string) (*ChatResponse, error) {
	cleaned := stripCodeFences(text)

	// Best-effort: extract the first balanced top-level JSON object from
	// the cleaned text in case the LLM emitted prose around the JSON.
	if extracted := extractFirstJSONObject(cleaned); extracted != "" {
		cleaned = extracted
	}

	var result ChatResponse
	if err := json.Unmarshal([]byte(cleaned), &result); err == nil {
		// Validate type field has a known value
		if result.Type != ChatResponseText && result.Type != ChatResponseRevisedPlan {
			return degradeToText(text, "LLM returned an unrecognized response type"), nil
		}
		// If type is revised_plan but RevisedPlan is missing/empty, degrade
		if result.Type == ChatResponseRevisedPlan && (result.RevisedPlan == nil || len(result.RevisedPlan.Commands) == 0) {
			return degradeToText(text, "LLM indicated a revised plan but did not produce one"), nil
		}
		return &result, nil
	}

	// JSON parse failed entirely. Surface the raw model output as a text
	// reply rather than failing the chat turn.
	return degradeToText(text, "I had trouble formatting my response"), nil
}

// degradeToText wraps raw LLM output (or a fallback message) in a
// well-formed text-type ChatResponse.
func degradeToText(rawLLMOutput, prefix string) *ChatResponse {
	const maxRaw = 2000
	body := strings.TrimSpace(rawLLMOutput)
	if len(body) > maxRaw {
		body = body[:maxRaw] + "...[truncated]"
	}
	content := prefix
	if body != "" {
		content = prefix + ":\n\n" + body
	}
	return &ChatResponse{
		Type:        ChatResponseText,
		TextContent: content,
		Summary:     prefix,
	}
}

// extractFirstJSONObject finds the first balanced `{...}` substring in s.
// Returns "" if no balanced object is found. Naive but good enough for
// stripping prose that wraps a JSON object.
func extractFirstJSONObject(s string) string {
	start := strings.Index(s, "{")
	if start < 0 {
		return ""
	}
	depth := 0
	inStr := false
	escaped := false
	for i := start; i < len(s); i++ {
		c := s[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == '"' {
			inStr = !inStr
			continue
		}
		if inStr {
			continue
		}
		switch c {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
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
