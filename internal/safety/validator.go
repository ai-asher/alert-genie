package safety

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
)

// Validator validates commands for safety before execution.
type Validator interface {
	Validate(ctx context.Context, cmd Command) (*SafetyVerdict, error)
}

// commandValidator implements the 6-layer command safety validation.
type commandValidator struct {
	whitelist []WhitelistRule
	blacklist []BlacklistRule
	logger    *slog.Logger
}

// NewValidator creates a new command validator with default + extra rules.
func NewValidator(extraWhitelist []WhitelistRule, extraBlacklist []BlacklistRule, logger *slog.Logger) Validator {
	whitelist := DefaultWhitelist()
	whitelist = append(whitelist, extraWhitelist...)

	blacklist := DefaultBlacklist()
	blacklist = append(blacklist, extraBlacklist...)

	return &commandValidator{
		whitelist: whitelist,
		blacklist: blacklist,
		logger:    logger,
	}
}

// Validate runs the 6-layer safety check on a command.
func (v *commandValidator) Validate(ctx context.Context, cmd Command) (*SafetyVerdict, error) {
	raw := cmd.Raw

	v.logger.Debug("validating command",
		slog.String("command", raw),
		slog.String("type", cmd.CommandType),
		slog.String("target", cmd.Target),
	)

	// Layer 1: Structural validation
	if verdict := v.structuralCheck(raw); verdict != nil {
		v.logger.Warn("command failed structural check",
			slog.String("command", raw),
			slog.String("reason", verdict.Reason),
		)
		return verdict, nil
	}

	// Layer 2: Anti-obfuscation
	if verdict := v.antiObfuscationCheck(raw); verdict != nil {
		v.logger.Warn("command failed anti-obfuscation check",
			slog.String("command", raw),
			slog.String("reason", verdict.Reason),
		)
		return verdict, nil
	}

	// Layer 3: Blacklist check
	if verdict := v.blacklistCheck(raw); verdict != nil {
		v.logger.Warn("command matched blacklist",
			slog.String("command", raw),
			slog.String("rule", verdict.MatchedRule),
			slog.String("reason", verdict.Reason),
		)
		return verdict, nil
	}

	// Layer 4: Whitelist check
	verdict := v.whitelistCheck(raw, cmd.CommandType)
	if !verdict.Allowed {
		v.logger.Warn("command not in whitelist",
			slog.String("command", raw),
			slog.String("reason", verdict.Reason),
		)
		return verdict, nil
	}

	// Layer 5: Approved — return the verdict with risk level from whitelist match
	v.logger.Info("command approved",
		slog.String("command", raw),
		slog.String("matched_rule", verdict.MatchedRule),
		slog.String("risk_level", verdict.RiskLevel.String()),
	)
	return verdict, nil
}

// structuralCheck rejects commands with shell operators or excessive length.
func (v *commandValidator) structuralCheck(raw string) *SafetyVerdict {
	if len(raw) > 500 {
		return &SafetyVerdict{
			Allowed:     false,
			RiskLevel:   RiskCritical,
			MatchedRule: "structural:length",
			Reason:      fmt.Sprintf("command exceeds 500 characters (%d chars)", len(raw)),
		}
	}

	// Check for shell operators
	dangerousPatterns := []struct {
		pattern string
		name    string
	}{
		{`|`, "pipe operator"},
		{`&&`, "AND operator"},
		{`||`, "OR operator"},
		{`;`, "semicolon"},
		{`$(`, "command substitution $()"},
		{"`", "backtick command substitution"},
		{`>`, "output redirect"},
		{`>>`, "append redirect"},
		{`<`, "input redirect"},
		{`<<`, "heredoc"},
	}

	for _, p := range dangerousPatterns {
		if strings.Contains(raw, p.pattern) {
			return &SafetyVerdict{
				Allowed:     false,
				RiskLevel:   RiskCritical,
				MatchedRule: "structural:" + p.name,
				Reason:      fmt.Sprintf("command contains forbidden shell operator: %s", p.name),
			}
		}
	}

	// Reject newlines
	if strings.ContainsAny(raw, "\n\r") {
		return &SafetyVerdict{
			Allowed:     false,
			RiskLevel:   RiskCritical,
			MatchedRule: "structural:newline",
			Reason:      "command contains newline characters",
		}
	}

	return nil
}

var (
	// base64Pattern matches 20+ consecutive base64 characters (suspicious encoded payloads).
	base64Pattern = regexp.MustCompile(`[A-Za-z0-9+/=]{20,}`)
	// hexEscapePattern matches hex escapes like \xNN.
	hexEscapePattern = regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	// octalEscapePattern matches octal escapes like \NNN.
	octalEscapePattern = regexp.MustCompile(`\\[0-7]{3}`)
	// unicodeEscapePattern matches unicode escapes like \uNNNN.
	unicodeEscapePattern = regexp.MustCompile(`\\u[0-9a-fA-F]{4}`)
	// urlEncodingPattern matches URL encoding like %NN.
	urlEncodingPattern = regexp.MustCompile(`%[0-9a-fA-F]{2}`)
)

// antiObfuscationCheck rejects commands with encoded/obfuscated content.
func (v *commandValidator) antiObfuscationCheck(raw string) *SafetyVerdict {
	checks := []struct {
		pattern *regexp.Regexp
		name    string
	}{
		{base64Pattern, "base64-like content (20+ chars)"},
		{hexEscapePattern, "hex escape sequence"},
		{octalEscapePattern, "octal escape sequence"},
		{unicodeEscapePattern, "unicode escape sequence"},
		{urlEncodingPattern, "URL encoding"},
	}

	for _, c := range checks {
		if c.pattern.MatchString(raw) {
			return &SafetyVerdict{
				Allowed:     false,
				RiskLevel:   RiskCritical,
				MatchedRule: "anti-obfuscation:" + c.name,
				Reason:      fmt.Sprintf("command contains suspicious %s", c.name),
			}
		}
	}

	return nil
}

// blacklistCheck rejects commands matching any blacklist pattern.
func (v *commandValidator) blacklistCheck(raw string) *SafetyVerdict {
	for _, rule := range v.blacklist {
		if rule.Pattern.MatchString(raw) {
			return &SafetyVerdict{
				Allowed:     false,
				RiskLevel:   RiskCritical,
				MatchedRule: "blacklist:" + rule.Pattern.String(),
				Reason:      rule.Reason,
			}
		}
	}
	return nil
}

// whitelistCheck ensures a command matches at least one whitelist entry.
func (v *commandValidator) whitelistCheck(raw, cmdType string) *SafetyVerdict {
	for _, rule := range v.whitelist {
		// If the rule specifies a command type, it must match
		if rule.CommandType != "" && cmdType != "" && rule.CommandType != cmdType {
			continue
		}
		if rule.Pattern.MatchString(raw) {
			return &SafetyVerdict{
				Allowed:     true,
				RiskLevel:   rule.RiskLevel,
				MatchedRule: rule.Name,
				Reason:      rule.Description,
			}
		}
	}

	return &SafetyVerdict{
		Allowed:     false,
		RiskLevel:   RiskCritical,
		MatchedRule: "whitelist:no_match",
		Reason:      "command does not match any whitelisted pattern",
	}
}
