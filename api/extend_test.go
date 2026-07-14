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

// --- Mutable Validator ---
// Unlike allowValidator (value receiver), this lets tests flip the validation
// result between the initial request and the extension call.

type mutableValidator struct {
	ok     bool
	reason string
}

func (m *mutableValidator) Validate(ctx context.Context, user, ref string) (bool, string, error) {
	return m.ok, m.reason, nil
}

// --- Tests ---

// TestExtendHappyPath: request → extend with still-valid context → 200.
func TestExtendHappyPath(t *testing.T) {
	v := &mutableValidator{ok: true, reason: ""}
	engine := auth.NewEngine(map[string]providers.ContextValidator{"pagerduty": v})
	st := store.New(fakeIssuer{})
	st.SetSessionLimits(60*time.Minute, 4*time.Hour, 15*time.Minute)
	srv := &Server{Engine: engine, Issuer: fakeIssuer{}, Store: st, TTL: 60 * time.Minute}

	// 1. Request a token
	reqBody, _ := json.Marshal(models.AccessRequest{
		UserIdentity: "alice", Resource: "db",
		JustificationType: "pagerduty", JustificationRef: "INC1",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/access/request", bytes.NewReader(reqBody))
	srv.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("request code=%d body=%s", rec.Code, rec.Body.String())
	}
	var grant models.AccessResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &grant)
	if grant.TokenID == "" {
		t.Fatal("expected token_id in response")
	}

	// 2. Extend it
	extBody, _ := json.Marshal(models.ExtensionRequest{
		TokenID: grant.TokenID, UserIdentity: "alice",
		JustificationType: "pagerduty", JustificationRef: "INC1",
	})
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/access/extend", bytes.NewReader(extBody))
	srv.Router().ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("extend code=%d body=%s", rec2.Code, rec2.Body.String())
	}
	var extResp models.ExtensionResponse
	_ = json.Unmarshal(rec2.Body.Bytes(), &extResp)
	if !extResp.Extended {
		t.Errorf("expected extended=true, got reason=%q", extResp.Reason)
	}
}

// TestExtendRevokesWhenContextInvalid: context changed to invalid → 403 + revoked.
func TestExtendRevokesWhenContextInvalid(t *testing.T) {
	v := &mutableValidator{ok: true}
	engine := auth.NewEngine(map[string]providers.ContextValidator{"pagerduty": v})
	st := store.New(fakeIssuer{})
	srv := &Server{Engine: engine, Issuer: fakeIssuer{}, Store: st, TTL: 60 * time.Minute}

	// 1. Request token (context valid)
	reqBody, _ := json.Marshal(models.AccessRequest{
		UserIdentity: "alice", Resource: "db",
		JustificationType: "pagerduty", JustificationRef: "INC1",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/access/request", bytes.NewReader(reqBody))
	srv.Router().ServeHTTP(rec, req)
	var grant models.AccessResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &grant)

	// 2. Flip context to invalid (simulating incident resolved)
	v.ok = false
	v.reason = "incident resolved"

	// 3. Attempt extend
	extBody, _ := json.Marshal(models.ExtensionRequest{
		TokenID: grant.TokenID, UserIdentity: "alice",
		JustificationType: "pagerduty", JustificationRef: "INC1",
	})
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/access/extend", bytes.NewReader(extBody))
	srv.Router().ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusForbidden {
		t.Fatalf("extend code=%d, want 403; body=%s", rec2.Code, rec2.Body.String())
	}
	var extResp models.ExtensionResponse
	_ = json.Unmarshal(rec2.Body.Bytes(), &extResp)
	if extResp.Extended {
		t.Error("expected extended=false when context invalid")
	}
	// Token should now be revoked
	if st.Get(grant.TokenID) != nil {
		t.Error("expected token to be revoked after failed extension")
	}
}

// TestExtendUnknownToken: 404 when token doesn't exist.
func TestExtendUnknownToken(t *testing.T) {
	engine := auth.NewEngine(map[string]providers.ContextValidator{"pagerduty": &mutableValidator{ok: true}})
	st := store.New(fakeIssuer{})
	srv := &Server{Engine: engine, Issuer: fakeIssuer{}, Store: st, TTL: time.Minute}

	extBody, _ := json.Marshal(models.ExtensionRequest{
		TokenID: "nonexistent", UserIdentity: "alice",
		JustificationType: "pagerduty", JustificationRef: "INC1",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/access/extend", bytes.NewReader(extBody))
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("extend code=%d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

// TestExtendMissingTokenID: 400 when token_id is empty.
func TestExtendMissingTokenID(t *testing.T) {
	srv := &Server{Engine: auth.NewEngine(nil), Issuer: fakeIssuer{}, Store: store.New(nil), TTL: time.Minute}

	extBody, _ := json.Marshal(models.ExtensionRequest{
		TokenID: "", UserIdentity: "alice",
		JustificationType: "pagerduty", JustificationRef: "INC1",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/access/extend", bytes.NewReader(extBody))
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("extend code=%d, want 400", rec.Code)
	}
}

// TestExtendInvalidJSON: 400 on malformed body.
func TestExtendInvalidJSON(t *testing.T) {
	srv := &Server{Engine: auth.NewEngine(nil), Issuer: fakeIssuer{}, Store: store.New(nil), TTL: time.Minute}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/access/extend", bytes.NewReader([]byte("not json")))
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("extend code=%d, want 400", rec.Code)
	}
}

// TestExtendWrongMethod: 405 on GET.
func TestExtendWrongMethod(t *testing.T) {
	srv := &Server{Engine: auth.NewEngine(nil), Issuer: fakeIssuer{}, Store: store.New(nil), TTL: time.Minute}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/access/extend", nil)
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("extend code=%d, want 405", rec.Code)
	}
}