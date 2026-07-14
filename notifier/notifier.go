// Package notifier delivers "impending expiration" alerts to Slack,
// Microsoft Teams, or the CLI/log sink. It is a fire-and-forget helper —
// delivery failures are logged but never block the caller.
package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/example/jit-access-broker/models"
)

// Notifier is the abstraction every concrete notifier implements.
type Notifier interface {
	NotifyExpiring(ctx context.Context, t *models.IssuedToken, timeLeft time.Duration) error
}

// MultiNotifier fans out a notification to all registered child notifiers.
type MultiNotifier struct {
	Children []Notifier
}

// NotifyExpiring calls every child notifier, collecting errors but never
// aborting early — one broken sink must not prevent the others.
func (m *MultiNotifier) NotifyExpiring(ctx context.Context, t *models.IssuedToken, timeLeft time.Duration) error {
	var errs []error
	for _, c := range m.Children {
		if c == nil {
			continue
		}
		if err := c.NotifyExpiring(ctx, t, timeLeft); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("notifier errors: %v", errs)
	}
	return nil
}

// LogNotifier writes the alert to the standard logger. This is the default
// sink used by the CLI and in tests.
type LogNotifier struct{}

// NotifyExpiring logs the impending-expiration message.
func (LogNotifier) NotifyExpiring(_ context.Context, t *models.IssuedToken, timeLeft time.Duration) error {
	msg := fmt.Sprintf("⚠️  TOKEN EXPIRING: token %s (user=%s, resource=%s) expires in %s — run extend to renew",
		t.ID, t.User, t.Resource, timeLeft.Round(time.Second))
	log.Println(msg)
	fmt.Println(msg) // also print to stdout for CLI visibility
	return nil
}

// SlackNotifier posts the alert to a Slack incoming webhook.
type SlackNotifier struct {
	WebhookURL string
	Client     *http.Client
}

// NotifyExpiring POSTs a Slack message block.
func (s *SlackNotifier) NotifyExpiring(ctx context.Context, t *models.IssuedToken, timeLeft time.Duration) error {
	if s.WebhookURL == "" {
		return nil
	}
	if s.Client == nil {
		s.Client = &http.Client{Timeout: 5 * time.Second}
	}
	payload := map[string]any{
		"text": fmt.Sprintf(":warning: *Token Expiring*\nToken `%s` (user: %s, resource: %s) expires in %s. Use the extend endpoint to renew.",
			t.ID, t.User, t.Resource, timeLeft.Round(time.Second)),
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("slack webhook returned %d", resp.StatusCode)
	}
	return nil
}

// TeamsNotifier posts the alert to a Microsoft Teams incoming webhook.
type TeamsNotifier struct {
	WebhookURL string
	Client     *http.Client
}

// NotifyExpiring POSTs a Teams message card.
func (t2 *TeamsNotifier) NotifyExpiring(ctx context.Context, t *models.IssuedToken, timeLeft time.Duration) error {
	if t2.WebhookURL == "" {
		return nil
	}
	if t2.Client == nil {
		t2.Client = &http.Client{Timeout: 5 * time.Second}
	}
	payload := map[string]any{
		"@type":   "MessageCard",
		"@context": "https://schema.org/extensions",
		"summary": "Token Expiring",
		"title":   "⚠️ JIT Token Expiring",
		"text": fmt.Sprintf("Token `%s` (user: %s, resource: %s) expires in %s. Use the extend endpoint to renew.",
			t.ID, t.User, t.Resource, timeLeft.Round(time.Second)),
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t2.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t2.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("teams webhook returned %d", resp.StatusCode)
	}
	return nil
}

// NoopNotifier does nothing — used in tests where you don't care about delivery.
type NoopNotifier struct{}

func (NoopNotifier) NotifyExpiring(context.Context, *models.IssuedToken, time.Duration) error { return nil }