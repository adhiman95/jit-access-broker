package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/example/jit-access-broker/api"
	"github.com/example/jit-access-broker/auth"
	"github.com/example/jit-access-broker/models"
	"github.com/example/jit-access-broker/providers"
	"github.com/example/jit-access-broker/store"
)

// mockPagerDuty returns acknowledged + alice as assignee.
func mockPagerDuty(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"incident": map[string]any{
				"status": "acknowledged",
				"assignments": []map[string]any{
					{"assignee": map[string]any{"id": "U1", "summary": "alice@example.com"}},
				},
			},
		})
	}))
}

// mockVaultWithCounter tracks revocations.
func mockVaultWithCounter(revoked *int) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/token/create", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": "vtok_live", "lease_duration": 60},
		})
	})
	mux.HandleFunc("/v1/auth/token/revoke", func(w http.ResponseWriter, r *http.Request) {
		*revoked++
		w.WriteHeader(http.StatusNoContent)
	})
	return httptest.NewServer(mux)
}

func TestIntegrationHappyPath(t *testing.T) {
	pdSrv := mockPagerDuty(t)
	defer pdSrv.Close()
	var revoked int
	vSrv := mockVaultWithCounter(&revoked)
	defer vSrv.Close()

	pd := &providers.PagerDutyClient{BaseURL: pdSrv.URL, APIToken: "tok"}
	vault := &providers.VaultClient{Addr: vSrv.URL, Token: "root"}
	engine := auth.NewEngine(map[string]providers.ContextValidator{"pagerduty": pd})
	st := store.New(vault)
	srv := api.NewServer(engine, vault, st, 60*time.Second)
	httpSrv := httptest.NewServer(srv.Router())
	defer httpSrv.Close()

	body, _ := json.Marshal(models.AccessRequest{
		UserIdentity: "alice@example.com", Resource: "prod-db",
		JustificationType: "pagerduty", JustificationRef: "INC1",
	})
	resp, err := http.Post(httpSrv.URL+"/api/v1/access/request", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var ar models.AccessResponse
	_ = json.NewDecoder(resp.Body).Decode(&ar)
	if !ar.Granted || ar.Token == "" {
		t.Fatalf("not granted: %+v", ar)
	}
	if !strings.HasPrefix(ar.Token, "vtok") {
		t.Errorf("token = %q, want vtok prefix", ar.Token)
	}
}

func TestIntegrationValidationFailForbidden(t *testing.T) {
	pdSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"incident": map[string]any{
				"status": "resolved", // wrong status → must be acknowledged
				"assignments": []map[string]any{
					{"assignee": map[string]any{"id": "U1", "summary": "alice@example.com"}},
				},
			},
		})
	}))
	defer pdSrv.Close()
	vSrv := mockVaultWithCounter(new(int))
	defer vSrv.Close()

	pd := &providers.PagerDutyClient{BaseURL: pdSrv.URL, APIToken: "tok"}
	vault := &providers.VaultClient{Addr: vSrv.URL, Token: "root"}
	engine := auth.NewEngine(map[string]providers.ContextValidator{"pagerduty": pd})
	st := store.New(vault)
	srv := api.NewServer(engine, vault, st, time.Minute)
	httpSrv := httptest.NewServer(srv.Router())
	defer httpSrv.Close()

	body, _ := json.Marshal(models.AccessRequest{
		UserIdentity: "alice@example.com", Resource: "prod-db",
		JustificationType: "pagerduty", JustificationRef: "INC1",
	})
	resp, err := http.Post(httpSrv.URL+"/api/v1/access/request", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestIntegrationAutoRevocation(t *testing.T) {
	pdSrv := mockPagerDuty(t)
	defer pdSrv.Close()
	var revoked int
	vSrv := mockVaultWithCounter(&revoked)
	defer vSrv.Close()

	pd := &providers.PagerDutyClient{BaseURL: pdSrv.URL, APIToken: "tok"}
	vault := &providers.VaultClient{Addr: vSrv.URL, Token: "root"}
	engine := auth.NewEngine(map[string]providers.ContextValidator{"pagerduty": pd})
	st := store.New(vault)
	srv := api.NewServer(engine, vault, st, 400*time.Millisecond) // very short TTL

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go st.Run(ctx)

	httpSrv := httptest.NewServer(srv.Router())
	defer httpSrv.Close()

	body, _ := json.Marshal(models.AccessRequest{
		UserIdentity: "alice@example.com", Resource: "prod-db",
		JustificationType: "pagerduty", JustificationRef: "INC1",
	})
	resp, err := http.Post(httpSrv.URL+"/api/v1/access/request", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	// wait up to 3s for auto-revocation
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && revoked == 0 {
		time.Sleep(50 * time.Millisecond)
	}
	if revoked == 0 {
		t.Fatal("auto-revocation did not occur within 3s")
	}
	t.Logf("auto-revocation confirmed: vault revoke called %d time(s)", revoked)
}