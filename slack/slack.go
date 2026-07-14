// Package slack implements a Slack slash-command handler that lets
// developers request JIT access directly from Slack ChatOps.
//
//	Command syntax:
//	  /jit <resource> <justification_type> <justification_ref>
//
//	Examples:
//	  /jit prod-db-readonly pagerduty Q3ABC123
//	  /jit prod-vault jira DEV-456
package slack

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/example/jit-access-broker/auth"
	"github.com/example/jit-access-broker/models"
	"github.com/example/jit-access-broker/providers"
	"github.com/example/jit-access-broker/store"
)

// Handler processes incoming Slack slash commands.
type Handler struct {
	Engine     *auth.Engine
	Issuer     providers.TokenIssuer
	Store      *store.Store
	TTL        time.Duration
	SigningSecret string
	// UserEmailMap maps Slack user_id → email identity (for contextual validation).
	// If a user_id is not in this map and BotToken is set, the handler will
	// attempt to look up the email via the Slack Web API.
	UserEmailMap map[string]string
	// BotToken is an optional Slack bot token (xoxb-...) for user email lookup.
	BotToken string
}

// SlashCommand represents the parsed payload from Slack.
type SlashCommand struct {
	Token       string
	Command     string
	Text        string
	UserID      string
	UserName    string
	ResponseURL string
}

// ParseSlackCommand parses an application/x-www-form-urlencoded Slack request.
func ParseSlackCommand(r *http.Request) (*SlashCommand, error) {
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("parse form: %w", err)
	}
	return &SlashCommand{
		Token:       r.PostFormValue("token"),
		Command:     r.PostFormValue("command"),
		Text:        r.PostFormValue("text"),
		UserID:      r.PostFormValue("user_id"),
		UserName:    r.PostFormValue("user_name"),
		ResponseURL: r.PostFormValue("response_url"),
	}, nil
}

// ParseCommandText splits the /jit text into resource, type, and ref.
// Expected format: "<resource> <justification_type> <justification_ref>"
func ParseCommandText(text string) (resource, jtype, jref string, err error) {
	parts := strings.Fields(strings.TrimSpace(text))
	if len(parts) < 3 {
		return "", "", "", fmt.Errorf("usage: /jit <resource> <justification_type> <justification_ref>")
	}
	return parts[0], parts[1], parts[2], nil
}

// Handle is the http.HandlerFunc that processes /slack/command.
func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeSlackError(w, "method not allowed")
		return
	}

	cmd, err := ParseSlackCommand(r)
	if err != nil {
		writeSlackError(w, "failed to parse command: "+err.Error())
		return
	}

	// Verify signing token (if configured)
	if h.SigningSecret != "" && cmd.Token != h.SigningSecret {
		writeSlackError(w, "invalid Slack token")
		return
	}

	// Parse command text
	resource, jtype, jref, err := ParseCommandText(cmd.Text)
	if err != nil {
		writeSlackError(w, err.Error())
		return
	}

	// Resolve user email
	email := h.resolveEmail(cmd.UserID, cmd.UserName)
	if email == "" {
		writeSlackError(w, fmt.Sprintf("no email mapping for Slack user %s — add to slack.user_email_map in config", cmd.UserID))
		return
	}

	// Build access request
	req := models.AccessRequest{
		UserIdentity:      email,
		Resource:          resource,
		JustificationType: jtype,
		JustificationRef:  jref,
	}

	// Contextual validation
	res, err := h.Engine.Validate(context.Background(), req)
	if err != nil {
		writeSlackResponse(w, false, fmt.Sprintf("⚠️ Validation error: %s", res.Reason), "", "")
		return
	}
	if !res.OK {
		writeSlackResponse(w, false, fmt.Sprintf("❌ Access denied: %s", res.Reason), "", "")
		return
	}

	// Issue token
	tok, err := h.Issuer.Issue(context.Background(), email, resource, h.TTL)
	if err != nil {
		writeSlackResponse(w, false, fmt.Sprintf("❌ Token issue failed: %s", err.Error()), "", "")
		return
	}

	tok.JustificationType = jtype
	tok.JustificationRef = jref
	h.Store.Add(tok)

	// Success response
	msg := fmt.Sprintf("✅ Access granted to *%s* for *%s*\n", email, resource)
	msg += fmt.Sprintf("🎫 Token: `%s`\n", truncate(tok.Token, 30))
	msg += fmt.Sprintf("⏱️ Expires: %s (TTL: %dm)", tok.ExpiresAt.Format(time.RFC3339), int(h.TTL.Minutes()))
	writeSlackResponse(w, true, msg, tok.Token, tok.ID)
}

// resolveEmail maps a Slack user_id to an email identity.
func (h *Handler) resolveEmail(userID, userName string) string {
	if email, ok := h.UserEmailMap[userID]; ok {
		return email
	}
	// Fallback: construct from userName if map is empty
	if h.UserEmailMap == nil && userName != "" {
		return userName + "@slack.local"
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// SlackResponse is the JSON payload sent back to Slack.
type SlackResponse struct {
	ResponseType string `json:"response_type"` // "ephemeral" or "in_channel"
	Text         string `json:"text"`
}

func writeSlackResponse(w http.ResponseWriter, granted bool, msg, token, tokenID string) {
	resp := SlackResponse{
		ResponseType: "ephemeral", // only visible to the requester
		Text:         msg,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func writeSlackError(w http.ResponseWriter, msg string) {
	resp := SlackResponse{
		ResponseType: "ephemeral",
		Text:         "❌ " + msg,
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Slack-Error", url.PathEscape(msg))
	w.WriteHeader(http.StatusOK) // Slack always expects 200
	_ = json.NewEncoder(w).Encode(resp)
}