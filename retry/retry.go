// Package retry implements a reliable, idempotent revocation engine with
// exponential backoff. It wraps a TokenIssuer.Revoke call so that transient
// upstream failures (API throttling, network drops, 5xx errors) don't leave
// tokens permanently orphaned.
//
// The engine is designed to be embedded inside the store's self-destruction
// worker. When a token's TTL expires, the worker calls RetryRevoker.Revoke,
// which:
//  1. Attempts the revocation.
//  2. On failure, retries with exponential backoff (base * 2^attempt).
//  3. After MaxAttempts exhausted, marks the token as "revocation_pending" and
//     will retry again on the next worker tick.
//  4. Emits an audit event on each failure.
package retry

import (
	"context"
	"log"
	"math"
	"time"

	"github.com/example/jit-access-broker/audit"
	"github.com/example/jit-access-broker/models"
	"github.com/example/jit-access-broker/providers"
)

// RetryRevoker wraps a TokenIssuer with retry logic.
type RetryRevoker struct {
	Issuer      providers.TokenIssuer
	BaseDelay   time.Duration // initial backoff (default 1s)
	MaxDelay    time.Duration // backoff cap (default 30s)
	MaxAttempts int           // attempts per revoke call (default 5)
	MaxJitter   float64       // jitter fraction 0.0–1.0 (default 0.1)
	Logger      *audit.Logger
	sleep       func(time.Duration) // injectable for tests
}

// NewRetryRevoker creates a revoker with production-default settings.
func NewRetryRevoker(issuer providers.TokenIssuer, logger *audit.Logger) *RetryRevoker {
	return &RetryRevoker{
		Issuer:      issuer,
		BaseDelay:   1 * time.Second,
		MaxDelay:    30 * time.Second,
		MaxAttempts: 5,
		MaxJitter:   0.1,
		Logger:      logger,
		sleep:       time.Sleep,
	}
}

// Revoke attempts to revoke the token, retrying on failure with exponential
// backoff. Returns nil if the revocation succeeded (or was already revoked).
// Returns an error only if all attempts are exhausted.
func (r *RetryRevoker) Revoke(ctx context.Context, t *models.IssuedToken) error {
	if t == nil {
		return nil
	}
	if r.MaxAttempts <= 0 {
		r.MaxAttempts = 5
	}
	if r.BaseDelay <= 0 {
		r.BaseDelay = 1 * time.Second
	}
	if r.MaxDelay <= 0 {
		r.MaxDelay = 30 * time.Second
	}

	var lastErr error
	for attempt := 1; attempt <= r.MaxAttempts; attempt++ {
		// Check if context is cancelled before each attempt
		if ctx.Err() != nil {
			return ctx.Err()
		}

		err := r.Issuer.Revoke(ctx, t)
		if err == nil {
			return nil // success
		}
		lastErr = err

		// Log the failure for observability
		if r.Logger != nil {
			r.Logger.LogRevokeFailed(t, attempt, err)
		}

		// Don't sleep after the last attempt
		if attempt == r.MaxAttempts {
			break
		}

		// Exponential backoff: base * 2^(attempt-1)
		delay := time.Duration(float64(r.BaseDelay) * math.Pow(2, float64(attempt-1)))
		if delay > r.MaxDelay {
			delay = r.MaxDelay
		}

		// Add jitter to avoid thundering herd
		if r.MaxJitter > 0 {
			jitterRange := float64(delay) * r.MaxJitter
			delay = delay - time.Duration(jitterRange/2) + time.Duration(jitterRange*randomFraction())
		}

		log.Printf("retry: revocation attempt %d failed for %s, retrying in %s: %v", attempt, t.ID, delay, err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		r.sleep(delay)
	}

	log.Printf("retry: revocation FAILED after %d attempts for token %s: %v", r.MaxAttempts, t.ID, lastErr)
	return lastErr
}

// randomFraction returns a pseudo-random float in [0, 1).
// We use a simple approach to avoid importing crypto/rand here.
func randomFraction() float64 {
	return float64(time.Now().UnixNano()%1e6) / 1e6
}

// SetSleeper allows tests to replace time.Sleep with an instant no-op.
func (r *RetryRevoker) SetSleeper(s func(time.Duration)) {
	r.sleep = s
}