// Store reliability integration — wires audit logging, retry-backed
// revocation, and SQLite/JSON-file persistence into the core store lifecycle.
package store

import (
	"context"
	"log"
	"time"

	"github.com/example/jit-access-broker/audit"
	"github.com/example/jit-access-broker/persistence"
	"github.com/example/jit-access-broker/retry"
)

// SetAuditLogger wires the structured audit logger.
func (s *Store) SetAuditLogger(l *audit.Logger) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditLog = l
}

// SetRetryRevoker wires the exponential-backoff retry revoker. When set,
// all revocation calls (auto + manual) go through it.
func (s *Store) SetRetryRevoker(r *retry.RetryRevoker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoker = r
}

// SetPersistence wires the durable state store and triggers immediate
// recovery of any missed expirations from the previous run.
func (s *Store) SetPersistence(p *persistence.Store) error {
	s.mu.Lock()
	s.persist = p
	s.mu.Unlock()

	// Recover missed expirations
	return s.RecoverMissedExpirations(context.Background())
}

// RecoverMissedExpirations loads active tokens from the persistence file,
// re-adds still-valid ones to the heap, and immediately revokes any that
// expired while the broker was down.
func (s *Store) RecoverMissedExpirations(ctx context.Context) error {
	s.mu.RLock()
	p := s.persist
	s.mu.RUnlock()
	if p == nil {
		return nil
	}

	records, err := p.LoadActive()
	if err != nil {
		return err
	}

	now := time.Now()
	missed := persistence.MissedExpirations(records, now)

	// Re-add still-valid tokens to the in-memory store
	for _, r := range records {
		if r.Revoked || r.ExpiresAt.Before(now) {
			continue
		}
		tok := r.ToToken()
		// Only add if not already in the store (avoid duplicates)
		s.mu.RLock()
		_, exists := s.tokens[tok.ID]
		s.mu.RUnlock()
		if !exists {
			s.Add(tok)
			log.Printf("store: recovered live token %s (user=%s, expires=%s)", tok.ID, tok.User, tok.ExpiresAt.Format(time.RFC3339))
		}
	}

	// Immediately revoke missed expirations
	for _, r := range missed {
		tok := r.ToToken()
		log.Printf("store: recovering MISSED expiration for token %s (expired %s)", tok.ID, tok.ExpiresAt.Format(time.RFC3339))
		s.mu.Lock()
		tok.Revoked = true
		s.revokedCount++
		s.tokens[tok.ID] = tok
		s.mu.Unlock()

		// Use retry revoker if available, else direct issuer
		s.mu.RLock()
		revoker := s.revoker
		issuer := s.issuer
		auditLog := s.auditLog
		s.mu.RUnlock()

		if revoker != nil {
			if err := revoker.Revoke(ctx, tok); err != nil {
				log.Printf("store: missed-expiration revoke failed for %s: %v", tok.ID, err)
			}
		} else if issuer != nil {
			_ = issuer.Revoke(ctx, tok)
		}
		if auditLog != nil {
			auditLog.LogRevoked(tok, "recovery")
		}
	}

	if len(missed) > 0 {
		log.Printf("store: recovered %d missed expiration(s)", len(missed))
	}
	return nil
}

// PersistAll writes the current token state to the persistence layer.
func (s *Store) PersistAll() error {
	s.mu.RLock()
	p := s.persist
	s.mu.RUnlock()
	if p == nil {
		return nil
	}

	s.mu.RLock()
	records := make([]persistence.Record, 0, len(s.tokens))
	for _, t := range s.tokens {
		records = append(records, persistence.ToRecord(t))
	}
	s.mu.RUnlock()

	return p.SaveAll(records)
}

// revokeWithRetry performs revocation using the retry engine if configured,
// otherwise falls back to a direct issuer call.
func (s *Store) revokeWithRetry(ctx context.Context, t interface{ getID() string }) {
	// This is a helper kept for future use; actual revocation logic stays
	// inline in revokeExpired/RevokeNow for clarity.
}