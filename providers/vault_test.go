package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/example/jit-access-broker/models"
)

// newMockVault returns a mock Vault server plus a pointer to a counter that
// tracks how many tokens were revoked against it.
func newMockVault(t *testing.T) (*httptest.Server, *int32) {
	t.Helper()
	var revoked int32
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/auth/token/create", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		ttlSec, _ := body["ttl"].(float64)
		if ttlSec <= 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{
				"client_token":   "vtok_" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", ""),
				"lease_duration": int(ttlSec),
			},
		})
	})

	mux.HandleFunc("/v1/auth/token/revoke", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&revoked, 1)
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/v1/auth/token/lookup", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"id": "x", "ttl": 60, "renewable": false},
		})
	})

	return httptest.NewServer(mux), &revoked
}

func TestVaultIssueSuccess(t *testing.T) {
	srv, _ := newMockVault(t)
	defer srv.Close()
	v := &VaultClient{Addr: srv.URL, Token: "root"}

	tok, err := v.Issue(context.Background(), "alice", "prod-db", 60*time.Second)
	if err != nil {
		t.Fatalf("issue failed: %v", err)
	}
	if tok.Token == "" {
		t.Fatal("token empty")
	}
	if tok.Provider != "vault" {
		t.Errorf("provider = %q, want vault", tok.Provider)
	}
	if !tok.ExpiresAt.After(tok.IssuedAt) {
		t.Error("expires_at must be after issued_at")
	}
}

func TestVaultIssueNoAddr(t *testing.T) {
	v := &VaultClient{}
	_, err := v.Issue(context.Background(), "u", "r", time.Minute)
	if err == nil {
		t.Fatal("expected error for empty addr")
	}
}

func TestVaultRevokeSuccess(t *testing.T) {
	srv, revoked := newMockVault(t)
	defer srv.Close()
	v := &VaultClient{Addr: srv.URL, Token: "root"}

	err := v.Revoke(context.Background(), &models.IssuedToken{ID: "t1", Token: "vtok_abc"})
	if err != nil {
		t.Fatalf("revoke failed: %v", err)
	}
	if atomic.LoadInt32(revoked) != 1 {
		t.Errorf("revoke count = %d, want 1", *revoked)
	}
}

func TestVaultRevokeIdempotentNil(t *testing.T) {
	v := &VaultClient{Addr: "x", Token: "y"}
	if err := v.Revoke(context.Background(), nil); err != nil {
		t.Fatalf("nil revoke should be noop, got %v", err)
	}
}

func TestVaultLookup(t *testing.T) {
	srv, _ := newMockVault(t)
	defer srv.Close()
	v := &VaultClient{Addr: srv.URL, Token: "root"}
	lr, err := v.Lookup(context.Background(), "vtok_x")
	if err != nil {
		t.Fatalf("lookup failed: %v", err)
	}
	if lr.Data.ID == "" {
		t.Error("lookup returned empty id")
	}
}