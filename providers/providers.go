// Package providers contains the interface definitions and concrete
// implementations for the three categories of external system the broker
// talks to:
//
//   - ContextValidator   (PagerDuty, Jira) — verify the operator is genuinely
//     on-call / assigned to the referenced ticket.
//   - TokenIssuer        (Vault, AWS STS) — mint a short-lived credential and
//     revoke it on expiry.
package providers

import (
	"context"
	"time"

	"github.com/example/jit-access-broker/models"
)

// ContextValidator verifies that a user truly owns / is actively working the
// referenced operational context (incident or ticket).
type ContextValidator interface {
	// Validate returns (true, nil) when the user is the assigned engineer and
	// the referenced item is in an active state. Any other outcome is a
	// (false, reason) pair, or an error for transport-level failures.
	Validate(ctx context.Context, user string, ref string) (bool, string, error)
}

// TokenIssuer mints and revokes short-lived credentials at the target provider.
type TokenIssuer interface {
	// Issue creates a token for the requested resource with the supplied TTL.
	// The returned IssuedToken carries the opaque token string the caller will
	// hand to the operator.
	Issue(ctx context.Context, user, resource string, ttl time.Duration) (*models.IssuedToken, error)

	// Revoke invalidates a previously-issued token. It must be idempotent.
	Revoke(ctx context.Context, t *models.IssuedToken) error

	// Name identifies the provider (e.g. "vault", "aws").
	Name() string
}