// HashiCorp Vault provider — implements TokenIssuer. Uses the Vault token
// create / revoke endpoints against the /v1/auth/token endpoints. Designed
// to be exercised against an httptest mock server in tests; in production it
// points at a real Vault instance.
package providers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/example/jit-access-broker/models"
)

// VaultClient is the TokenIssuer backed by HashiCorp Vault.
type VaultClient struct {
	Addr      string
	Token     string
	HTTPClient *http.Client
}

// vaultCreateResp models the response of POST /v1/auth/token/create.
type vaultCreateResp struct {
	Auth struct {
		ClientToken string `json:"client_token"`
		LeaseDuration int  `json:"lease_duration"`
	} `json:"auth"`
}

// vaultLookupResp models the response of POST /v1/auth/token/lookup.
type vaultLookupResp struct {
	Data struct {
		ID             string `json:"id"`
		TTL            int    `json:"ttl"`
		Renewable      bool   `json:"renewable"`
	} `json:"data"`
}

// Issue mints a new child token against Vault with the supplied TTL.
func (v *VaultClient) Issue(ctx context.Context, user, resource string, ttl time.Duration) (*models.IssuedToken, error) {
	if v.Addr == "" {
		return nil, fmt.Errorf("vault: addr not configured")
	}
	// Build request body. ttl is expressed in seconds for Vault.
	body := map[string]any{
		"ttl":         int(ttl.Seconds()),
		"display_name": fmt.Sprintf("jit-%s-%s", user, resource),
		"metadata": map[string]string{
			"user":     user,
			"resource": resource,
			"purpose":  "jit-access-broker",
		},
	}
	bodyBytes, _ := json.Marshal(body)

	url := v.Addr + "/v1/auth/token/create"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", v.Token)
	req.Header.Set("Content-Type", "application/json")

	client := v.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault create: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("vault create: status %d: %s", resp.StatusCode, raw)
	}

	var vr vaultCreateResp
	if err := json.NewDecoder(resp.Body).Decode(&vr); err != nil {
		return nil, fmt.Errorf("vault create: decode: %w", err)
	}
	if vr.Auth.ClientToken == "" {
		return nil, fmt.Errorf("vault create: empty client_token")
	}

	now := time.Now().UTC()
	return &models.IssuedToken{
		ID:        newTokenID(),
		User:      user,
		Resource:  resource,
		Token:     vr.Auth.ClientToken,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
		Provider:  v.Name(),
	}, nil
}

// Revoke invalidates a previously-issued Vault token. Idempotent.
func (v *VaultClient) Revoke(ctx context.Context, t *models.IssuedToken) error {
	if t == nil || t.Token == "" {
		return nil
	}
	body, _ := json.Marshal(map[string]string{"token": t.Token})
	url := v.Addr + "/v1/auth/token/revoke"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", v.Token)
	req.Header.Set("Content-Type", "application/json")

	client := v.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("vault revoke: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vault revoke: status %d: %s", resp.StatusCode, raw)
	}
	return nil
}

// Lookup queries the TTL of a token (used by tests / introspection).
func (v *VaultClient) Lookup(ctx context.Context, token string) (*vaultLookupResp, error) {
	body, _ := json.Marshal(map[string]string{"token": token})
	url := v.Addr + "/v1/auth/token/lookup"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", v.Token)
	req.Header.Set("Content-Type", "application/json")

	client := v.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("lookup status %d", resp.StatusCode)
	}
	var lr vaultLookupResp
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return nil, err
	}
	return &lr, nil
}

// Name returns the provider identifier.
func (v *VaultClient) Name() string { return "vault" }

// newTokenID generates a short opaque hex id for internal tracking.
func newTokenID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "tok_" + hex.EncodeToString(b)
}