package slack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/example/jit-access-broker/auth"
	"github.com/example/jit-access-broker/providers"
	"github.com/example/jit-access-broker/store"
)

// stubValidator is a controllable ContextValidator for testing.
type stubValidator struct {
	ok     bool
	reason string
}

func (m *stubValidator) Validate(_ context.Context, user, ref string) (bool, string, error) {
	return m.ok, m.reason, nil
}

func TestParseCommandText(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantRes   string
		wantType  string
		wantRef   string
		wantError bool
	}{
		{"valid 3 args", "prod-db pagerduty INC123", "prod-db", "pagerduty", "INC123", false},
		{"valid 4 args (extra ignored)", "prod-db pagerduty INC123 extra", "prod-db", "pagerduty", "INC123", false},
		{"too few args", "prod-db pagerduty", "", "", "", true},
		{"empty string", "", "", "", "", true},
		{"extra whitespace", "  prod-db   pagerduty   INC123  ", "prod-db", "pagerduty", "INC123", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, jtype, jref, err := ParseCommandText(tt.input)
			if (err != nil) != tt.wantError {
				t.Errorf("ParseCommandText(%q) error = %v, wantError %v", tt.input, err, tt.wantError)
			}
			if !tt.wantError {
				if res != tt.wantRes || jtype != tt.wantType || jref != tt.wantRef {
					t.Errorf("ParseCommandText(%q) = (%q,%q,%q), want (%q,%q,%q)",
						tt.input, res, jtype, jref, tt.wantRes, tt.wantType, tt.wantRef)
				}
			}
		})
	}
}

func TestParseSlackCommand(t *testing.T) {
	body := "token=abc123&command=%2Fjit&text=prod-db+pagerduty+INC123&user_id=U12345&user_name=jdoe&response_url=https%3A%2F%2Fhooks.slack.com"
	req := httptest.NewRequest(http.MethodPost, "/slack/command", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	cmd, err := ParseSlackCommand(req)
	if err != nil {
		t.Fatalf("ParseSlackCommand error: %v", err)
	}
	if cmd.Token != "abc123" {
		t.Errorf("Token = %q, want %q", cmd.Token, "abc123")
	}
	if cmd.UserID != "U12345" {
		t.Errorf("UserID = %q, want %q", cmd.UserID, "U12345")
	}
	if cmd.UserName != "jdoe" {
		t.Errorf("UserName = %q, want %q", cmd.UserName, "jdoe")
	}
	if cmd.Text != "prod-db pagerduty INC123" {
		t.Errorf("Text = %q", cmd.Text)
	}
}

func TestHandlerRejectsInvalidMethod(t *testing.T) {
	h := &Handler{}
	req := httptest.NewRequest(http.MethodGet, "/slack/command", nil)
	rr := httptest.NewRecorder()
	h.Handle(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 (Slack always wants 200), got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "method not allowed") {
		t.Errorf("expected error message, got: %s", rr.Body.String())
	}
}

func TestHandlerRejectsInvalidToken(t *testing.T) {
	h := &Handler{SigningSecret: "secret123"}
	body := "token=WRONG&command=%2Fjit&text=prod-db+pagerduty+INC123&user_id=U12345&user_name=jdoe"
	req := httptest.NewRequest(http.MethodPost, "/slack/command", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.Handle(rr, req)

	if !strings.Contains(rr.Body.String(), "invalid Slack token") {
		t.Errorf("expected invalid token error, got: %s", rr.Body.String())
	}
}

func TestHandlerRejectsMalformedCommand(t *testing.T) {
	h := &Handler{}
	body := "token=&command=%2Fjit&text=only-one-arg&user_id=U12345&user_name=jdoe"
	req := httptest.NewRequest(http.MethodPost, "/slack/command", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.Handle(rr, req)

	if !strings.Contains(rr.Body.String(), "usage:") {
		t.Errorf("expected usage error, got: %s", rr.Body.String())
	}
}

func TestHandlerRejectsUnmappedUser(t *testing.T) {
	h := &Handler{
		SigningSecret: "",
		UserEmailMap:  map[string]string{"OTHER": "mapped@example.com"},
	}
	body := "token=&command=%2Fjit&text=prod-db+pagerduty+INC123&user_id=U_UNMAPPED&user_name=jdoe"
	req := httptest.NewRequest(http.MethodPost, "/slack/command", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.Handle(rr, req)

	if !strings.Contains(rr.Body.String(), "no email mapping") {
		t.Errorf("expected email mapping error, got: %s", rr.Body.String())
	}
}

func TestHandlerFullSuccessFlow(t *testing.T) {
	issuer := &providers.DemoIssuer{}
	st := store.New(issuer)

	// Build a real engine with a stub validator
	engine := auth.NewEngine(map[string]providers.ContextValidator{
		"pagerduty": &stubValidator{ok: true},
	})

	h := &Handler{
		Engine:       engine,
		Issuer:       issuer,
		Store:        st,
		TTL:          60 * time.Minute,
		UserEmailMap: map[string]string{"U12345": "dev@example.com"},
	}

	body := "token=&command=%2Fjit&text=prod-db+pagerduty+INC123&user_id=U12345&user_name=jdoe"
	req := httptest.NewRequest(http.MethodPost, "/slack/command", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.Handle(rr, req)

	respBody := rr.Body.String()
	if !strings.Contains(respBody, "Access granted") {
		t.Errorf("expected success message, got: %s", respBody)
	}
	if !strings.Contains(respBody, "prod-db") {
		t.Errorf("expected resource name in message, got: %s", respBody)
	}

	// Verify token was added to store
	live := st.List()
	if len(live) != 1 {
		t.Errorf("expected 1 live token, got %d", len(live))
	}
}

func TestHandlerValidationDenied(t *testing.T) {
	issuer := &providers.DemoIssuer{}
	st := store.New(issuer)

	engine := auth.NewEngine(map[string]providers.ContextValidator{
		"pagerduty": &stubValidator{ok: false, reason: "user not assigned"},
	})

	h := &Handler{
		Engine:       engine,
		Issuer:       issuer,
		Store:        st,
		TTL:          60 * time.Minute,
		UserEmailMap: map[string]string{"U12345": "dev@example.com"},
	}

	body := "token=&command=%2Fjit&text=prod-db+pagerduty+INC123&user_id=U12345&user_name=jdoe"
	req := httptest.NewRequest(http.MethodPost, "/slack/command", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.Handle(rr, req)

	respBody := rr.Body.String()
	if !strings.Contains(respBody, "Access denied") {
		t.Errorf("expected denial message, got: %s", respBody)
	}

	// Verify NO token was issued
	live := st.List()
	if len(live) != 0 {
		t.Errorf("expected 0 tokens after denial, got %d", len(live))
	}
}

func TestResolveEmailFallback(t *testing.T) {
	h := &Handler{}
	// With no map and a userName, should construct fallback
	email := h.resolveEmail("U123", "jdoe")
	if email != "jdoe@slack.local" {
		t.Errorf("expected fallback email, got %s", email)
	}
}

func TestResolveEmailMapped(t *testing.T) {
	h := &Handler{
		UserEmailMap: map[string]string{"U123": "real@example.com"},
	}
	email := h.resolveEmail("U123", "jdoe")
	if email != "real@example.com" {
		t.Errorf("expected mapped email, got %s", email)
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input string
		n     int
		want  string
	}{
		{"short", 10, "short"},
		{"exactly10!", 5, "exact..."},
		{"", 5, ""},
	}
	for _, tt := range tests {
		got := truncate(tt.input, tt.n)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.n, got, tt.want)
		}
	}
}