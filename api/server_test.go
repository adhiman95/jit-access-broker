package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/example/jit-access-broker/auth"
	"github.com/example/jit-access-broker/models"
	"github.com/example/jit-access-broker/providers"
	"github.com/example/jit-access-broker/store"
)

type allowValidator struct {
	ok     bool
	reason string
}

func (a allowValidator) Validate(ctx context.Context, user, ref string) (bool, string, error) {
	return a.ok, a.reason, nil
}

type fakeIssuer struct{}

func (fakeIssuer) Issue(ctx context.Context, user, resource string, ttl time.Duration) (*models.IssuedToken, error) {
	now := time.Now().UTC()
	return &models.IssuedToken{
		ID: "tok_test", User: user, Resource: resource, Token: "secret",
		IssuedAt: now, ExpiresAt: now.Add(ttl), Provider: "fake",
	}, nil
}
func (fakeIssuer) Revoke(ctx context.Context, t *models.IssuedToken) error { return nil }
func (fakeIssuer) Name() string                                            { return "fake" }

func TestHealthz(t *testing.T) {
	srv := &Server{Engine: auth.NewEngine(nil), Issuer: fakeIssuer{}, Store: store.New(nil), TTL: time.Minute}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	srv.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz code = %d, want 200", rec.Code)
	}
}

func TestRequestHappyPath(t *testing.T) {
	engine := auth.NewEngine(map[string]providers.ContextValidator{"pagerduty": allowValidator{ok: true}})
	st := store.New(fakeIssuer{})
	srv := &Server{Engine: engine, Issuer: fakeIssuer{}, Store: st, TTL: 60 * time.Minute}

	body, _ := json.Marshal(models.AccessRequest{
		UserIdentity: "alice", Resource: "db", JustificationType: "pagerduty", JustificationRef: "INC1",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/access/request", bytes.NewReader(body))
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp models.AccessResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Granted || resp.Token == "" {
		t.Errorf("expected granted token, got %+v", resp)
	}
	if resp.TTLSeconds != 3600 {
		t.Errorf("ttl = %d, want 3600", resp.TTLSeconds)
	}
}

func TestRequestForbiddenOnValidationFail(t *testing.T) {
	engine := auth.NewEngine(map[string]providers.ContextValidator{"pagerduty": allowValidator{ok: false, reason: "not assigned"}})
	st := store.New(fakeIssuer{})
	srv := &Server{Engine: engine, Issuer: fakeIssuer{}, Store: st, TTL: time.Minute}

	body, _ := json.Marshal(models.AccessRequest{
		UserIdentity: "alice", Resource: "db", JustificationType: "pagerduty", JustificationRef: "INC1",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/access/request", bytes.NewReader(body))
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequestInvalidJSON(t *testing.T) {
	srv := &Server{Engine: auth.NewEngine(nil), Issuer: fakeIssuer{}, Store: store.New(nil), TTL: time.Minute}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/access/request", bytes.NewReader([]byte("not json")))
	srv.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", rec.Code)
	}
}

func TestListTokens(t *testing.T) {
	st := store.New(nil)
	st.Add(&models.IssuedToken{ID: "t1", User: "u", Resource: "r", Provider: "fake", ExpiresAt: time.Now().Add(time.Hour)})
	srv := &Server{Engine: auth.NewEngine(nil), Issuer: fakeIssuer{}, Store: st, TTL: time.Minute}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/access/tokens", nil)
	srv.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
}

func TestRevokeToken(t *testing.T) {
	st := store.New(fakeIssuer{})
	st.Add(&models.IssuedToken{ID: "t1", User: "u", Resource: "r", Token: "x", Provider: "fake", ExpiresAt: time.Now().Add(time.Hour)})
	srv := &Server{Engine: auth.NewEngine(nil), Issuer: fakeIssuer{}, Store: st, TTL: time.Minute}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/access/revoke/t1", nil)
	srv.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d body=%s", rec.Code, rec.Body.String())
	}
	// second call → 404 (already revoked)
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/access/revoke/t1", nil)
	srv.Router().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Errorf("second revoke code = %d, want 404", rec2.Code)
	}
}