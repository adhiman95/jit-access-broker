package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------- PagerDuty ----------------

func newMockPD(status, assigneeID string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Token token=") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		payload := map[string]any{
			"incident": map[string]any{
				"status": status,
				"assignments": []map[string]any{
					{"assignee": map[string]any{"id": assigneeID, "summary": "alice@example.com"}},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))
}

func TestPagerDutyValidateSuccess(t *testing.T) {
	srv := newMockPD("acknowledged", "U1")
	defer srv.Close()
	pd := &PagerDutyClient{BaseURL: srv.URL, APIToken: "tok"}
	ok, reason, err := pd.Validate(context.Background(), "alice@example.com", "INC1")
	if err != nil || !ok || reason != "" {
		t.Fatalf("expected ok, got ok=%v reason=%q err=%v", ok, reason, err)
	}
}

func TestPagerDutyValidateWrongStatus(t *testing.T) {
	srv := newMockPD("resolved", "U1")
	defer srv.Close()
	pd := &PagerDutyClient{BaseURL: srv.URL, APIToken: "tok"}
	ok, reason, err := pd.Validate(context.Background(), "alice@example.com", "INC1")
	if err != nil || ok {
		t.Fatalf("expected failure, got ok=%v err=%v", ok, err)
	}
	if !strings.Contains(reason, "resolved") {
		t.Errorf("reason should mention status, got %q", reason)
	}
}

func TestPagerDutyValidateWrongAssignee(t *testing.T) {
	srv := newMockPD("acknowledged", "U1")
	defer srv.Close()
	pd := &PagerDutyClient{BaseURL: srv.URL, APIToken: "tok"}
	ok, reason, err := pd.Validate(context.Background(), "bob@example.com", "INC1")
	if err != nil || ok {
		t.Fatalf("expected failure, got ok=%v err=%v", ok, err)
	}
	if !strings.Contains(reason, "not an assignee") {
		t.Errorf("reason should mention not an assignee, got %q", reason)
	}
}

func TestPagerDutyValidateNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	pd := &PagerDutyClient{BaseURL: srv.URL, APIToken: "tok"}
	ok, reason, err := pd.Validate(context.Background(), "alice@example.com", "GHOST")
	if err != nil || ok {
		t.Fatalf("expected failure, got ok=%v err=%v", ok, err)
	}
	if !strings.Contains(reason, "not found") {
		t.Errorf("reason should mention not found, got %q", reason)
	}
}

func TestPagerDutyValidateEmptyRef(t *testing.T) {
	pd := &PagerDutyClient{BaseURL: "x", APIToken: "tok"}
	ok, _, _ := pd.Validate(context.Background(), "u", "  ")
	if ok {
		t.Fatal("empty ref must fail")
	}
}

// ---------------- Jira ----------------

func newMockJira(status, assigneeEmail string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		payload := map[string]any{
			"fields": map[string]any{
				"status":   map[string]any{"name": status},
				"assignee": map[string]any{"accountId": "A1", "emailAddress": assigneeEmail},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))
}

func TestJiraValidateSuccess(t *testing.T) {
	srv := newMockJira("In Progress", "alice@example.com")
	defer srv.Close()
	j := &JiraClient{BaseURL: srv.URL, Username: "bot", APIToken: "tok"}
	ok, reason, err := j.Validate(context.Background(), "alice@example.com", "PROJ-1")
	if err != nil || !ok || reason != "" {
		t.Fatalf("expected ok, got ok=%v reason=%q err=%v", ok, reason, err)
	}
}

func TestJiraValidateWrongStatus(t *testing.T) {
	srv := newMockJira("Done", "alice@example.com")
	defer srv.Close()
	j := &JiraClient{BaseURL: srv.URL, Username: "bot", APIToken: "tok"}
	ok, reason, err := j.Validate(context.Background(), "alice@example.com", "PROJ-1")
	if err != nil || ok {
		t.Fatalf("expected failure, got ok=%v err=%v", ok, err)
	}
	if !strings.Contains(reason, "Done") {
		t.Errorf("reason should mention Done, got %q", reason)
	}
}

func TestJiraValidateWrongAssignee(t *testing.T) {
	srv := newMockJira("In Progress", "alice@example.com")
	defer srv.Close()
	j := &JiraClient{BaseURL: srv.URL, Username: "bot", APIToken: "tok"}
	ok, reason, err := j.Validate(context.Background(), "eve@example.com", "PROJ-1")
	if err != nil || ok {
		t.Fatalf("expected failure, got ok=%v err=%v", ok, err)
	}
	if !strings.Contains(reason, "not the assignee") {
		t.Errorf("reason should mention not the assignee, got %q", reason)
	}
}

func TestJiraValidateNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	j := &JiraClient{BaseURL: srv.URL, Username: "bot", APIToken: "tok"}
	ok, reason, err := j.Validate(context.Background(), "alice@example.com", "NOPE-9")
	if err != nil || ok {
		t.Fatalf("expected failure, got ok=%v err=%v", ok, err)
	}
	if !strings.Contains(reason, "not found") {
		t.Errorf("reason should mention not found, got %q", reason)
	}
}