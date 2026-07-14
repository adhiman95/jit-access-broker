// Package providers — DemoIssuer is a no-op TokenIssuer used when no real
// Vault/AWS backend is configured. It generates fake token strings so the
// broker binary can run end-to-end for local development and demos.
package providers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/example/jit-access-broker/models"
)

// DemoIssuer mints fake tokens for local development.
type DemoIssuer struct {
	// RevokedTokens records every Revoke call, for inspection in tests.
	RevokedTokens []string
}

// Issue creates a fake token string.
func (d *DemoIssuer) Issue(_ context.Context, user, resource string, ttl time.Duration) (*models.IssuedToken, error) {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	now := time.Now().UTC()
	return &models.IssuedToken{
		ID:        "tok_" + hex.EncodeToString(b),
		User:      user,
		Resource:  resource,
		Token:     fmt.Sprintf("demo-%s-%s", user, hex.EncodeToString(b)),
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
		Provider:  "demo",
	}, nil
}

// Revoke records the revocation (no real backend to call).
func (d *DemoIssuer) Revoke(_ context.Context, t *models.IssuedToken) error {
	if t != nil {
		d.RevokedTokens = append(d.RevokedTokens, t.Token)
	}
	return nil
}

// Name returns the provider identifier.
func (d *DemoIssuer) Name() string { return "demo" }