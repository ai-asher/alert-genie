package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// LarkNotifier sends notifications via Lark (Feishu) interactive cards.
type LarkNotifier struct {
	appID       string
	appSecret   string
	alertChatID string

	mu          sync.Mutex
	token       string
	tokenExpiry time.Time

	httpClient *http.Client
}

// NewLarkNotifier creates a new LarkNotifier.
func NewLarkNotifier(appID, appSecret, chatID string) *LarkNotifier {
	return &LarkNotifier{
		appID:       appID,
		appSecret:   appSecret,
		alertChatID: chatID,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// refreshToken obtains or refreshes the tenant access token from Lark.
func (l *LarkNotifier) refreshToken(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Token still valid with 5-minute buffer
	if l.token != "" && time.Now().Before(l.tokenExpiry.Add(-5*time.Minute)) {
		return nil
	}

	body, err := json.Marshal(map[string]string{
		"app_id":     l.appID,
		"app_secret": l.appSecret,
	})
	if err != nil {
		return fmt.Errorf("marshal token request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal",
		bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err := l.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send token request: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Code              int    `json:"code"`
		Msg               string `json:"msg"`
		TenantAccessToken string `json:"tenant_access_token"`
		Expire            int    `json:"expire"` // seconds
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode token response: %w", err)
	}
	if result.Code != 0 {
		return fmt.Errorf("lark token API error: code=%d msg=%s", result.Code, result.Msg)
	}

	l.token = result.TenantAccessToken
	l.tokenExpiry = time.Now().Add(time.Duration(result.Expire) * time.Second)
	return nil
}

// getToken returns a valid tenant access token, refreshing if necessary.
func (l *LarkNotifier) getToken(ctx context.Context) (string, error) {
	l.mu.Lock()
	valid := l.token != "" && time.Now().Before(l.tokenExpiry.Add(-5*time.Minute))
	l.mu.Unlock()

	if !valid {
		if err := l.refreshToken(ctx); err != nil {
			return "", err
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	return l.token, nil
}

// sendCard sends a Lark interactive card message and returns the message ID.
func (l *LarkNotifier) sendCard(ctx context.Context, chatID string, card map[string]any) (string, error) {
	token, err := l.getToken(ctx)
	if err != nil {
		return "", fmt.Errorf("get token: %w", err)
	}

	cardJSON, err := json.Marshal(card)
	if err != nil {
		return "", fmt.Errorf("marshal card: %w", err)
	}

	body, err := json.Marshal(map[string]any{
		"receive_id": chatID,
		"msg_type":   "interactive",
		"content":    string(cardJSON),
	})
	if err != nil {
		return "", fmt.Errorf("marshal message body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=chat_id",
		bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create send request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := l.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("send message: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read send response: %w", err)
	}

	var result struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			MessageID string `json:"message_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("decode send response: %w", err)
	}
	if result.Code != 0 {
		return "", fmt.Errorf("lark send API error: code=%d msg=%s", result.Code, result.Msg)
	}

	return result.Data.MessageID, nil
}

// updateCard updates an existing Lark interactive card message.
func (l *LarkNotifier) updateCard(ctx context.Context, messageID string, card map[string]any) error {
	token, err := l.getToken(ctx)
	if err != nil {
		return fmt.Errorf("get token: %w", err)
	}

	cardJSON, err := json.Marshal(card)
	if err != nil {
		return fmt.Errorf("marshal card: %w", err)
	}

	body, err := json.Marshal(map[string]any{
		"content": string(cardJSON),
	})
	if err != nil {
		return fmt.Errorf("marshal update body: %w", err)
	}

	url := fmt.Sprintf("https://open.feishu.cn/open-apis/im/v1/messages/%s", messageID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create update request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := l.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("update message: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read update response: %w", err)
	}

	var result struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("decode update response: %w", err)
	}
	if result.Code != 0 {
		return fmt.Errorf("lark update API error: code=%d msg=%s", result.Code, result.Msg)
	}

	return nil
}

// SendAnalysis sends an analysis card to the alert chat.
func (l *LarkNotifier) SendAnalysis(ctx context.Context, card AnalysisCard) (string, error) {
	larkCard := buildAnalysisCard(card)
	return l.sendCard(ctx, l.alertChatID, larkCard)
}

// SendHealingPlan sends a healing plan card with approval buttons to the alert chat.
func (l *LarkNotifier) SendHealingPlan(ctx context.Context, card HealingPlanCard) (string, error) {
	larkCard := buildHealingPlanCard(card)
	return l.sendCard(ctx, l.alertChatID, larkCard)
}

// UpdateProgress updates an existing message with execution progress.
func (l *LarkNotifier) UpdateProgress(ctx context.Context, messageID string, progress ExecutionProgress) error {
	larkCard := buildProgressCard(progress)
	return l.updateCard(ctx, messageID, larkCard)
}

// SendExecutionComplete updates an existing message with execution completion status.
func (l *LarkNotifier) SendExecutionComplete(ctx context.Context, messageID string, success bool, summary string) error {
	larkCard := buildCompletionCard(success, summary)
	return l.updateCard(ctx, messageID, larkCard)
}
