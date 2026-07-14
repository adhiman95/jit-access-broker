// Package store provides the in-memory tracking of issued tokens and the
// concurrent self-destruction worker. The worker consumes a min-heap priority
// queue ordered by ExpiresAt and calls the configured TokenIssuer.Revoke the
// instant a token's TTL elapses.
//
// The store also runs a warning worker that fires an "impending expiration"
// notification WarningBeforeExpiry before each token expires, and enforces the
// MaxSessionDuration ceiling across all extensions.
//
// The store is concurrency-safe; the worker honours a cancellable context so
// it can be shut down gracefully alongside the HTTP server.
package store

import (
	"container/heap"
	"context"
	"log"
	"sync"
	"time"

	"github.com/example/jit-access-broker/audit"
	"github.com/example/jit-access-broker/models"
	"github.com/example/jit-access-broker/notifier"
	"github.com/example/jit-access-broker/persistence"
	"github.com/example/jit-access-broker/providers"
	"github.com/example/jit-access-broker/retry"
)

// ExtendResult is returned by Extend() to communicate the outcome.
type ExtendResult struct {
	Extended       bool
	Token          *models.IssuedToken
	NewExpiresAt   time.Time
	MaxSessionAt   time.Time
	ExtensionsLeft int
	Reason         string
}

// Store holds live issued tokens and dispatches revocations.
type Store struct {
	mu     sync.RWMutex
	tokens map[string]*models.IssuedToken
	pq     *tokenHeap
	issuer providers.TokenIssuer

	// revokedCount tracks how many tokens have been auto-revoked — used by
	// tests/metrics to verify the worker actually fired.
	revokedCount int

	// revokedChan (when non-nil) receives the id of each token the worker
	// revokes. Tests use it to deterministically observe expiry.
	revokedChan chan string

	// Configurable session-level guardrails
	ttl              time.Duration
	maxSession       time.Duration
	warningBefore    time.Duration
	notifier         notifier.Notifier

	// warnedChan (when non-nil) receives the id of each token that triggered
	// the warning notification. Tests use it to verify the warning fired.
	warnedChan chan string

	// Production reliability features
	auditLog *audit.Logger
	revoker  *retry.RetryRevoker
	persist  *persistence.Store
}

// New constructs an empty Store bound to the given TokenIssuer.
func New(issuer providers.TokenIssuer) *Store {
	return &Store{
		tokens:        make(map[string]*models.IssuedToken),
		pq:            &tokenHeap{},
		issuer:        issuer,
		ttl:           models.MaxTTL,
		maxSession:    models.MaxSessionDuration,
		warningBefore: models.WarningBeforeExpiry,
		notifier:      notifier.NoopNotifier{},
	}
}

// SetSessionLimits configures the TTL, max session ceiling and warning window.
func (s *Store) SetSessionLimits(ttl, maxSession, warningBefore time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ttl = ttl
	s.maxSession = maxSession
	s.warningBefore = warningBefore
}

// SetNotifier wires the notifier sink for impending-expiry alerts.
func (s *Store) SetNotifier(n notifier.Notifier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n != nil {
		s.notifier = n
	}
}

// SetRevokedChan wires an observation channel used by tests. Pass nil to
// disable. Each auto-revoked token id is sent once.
func (s *Store) SetRevokedChan(c chan string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokedChan = c
}

// SetWarnedChan wires an observation channel for warning notifications.
func (s *Store) SetWarnedChan(c chan string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.warnedChan = c
}

// Add registers a freshly-issued token and pushes it onto the expiry heap.
func (s *Store) Add(t *models.IssuedToken) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Initialise OriginalIssuedAt if not set (first issue)
	if t.OriginalIssuedAt.IsZero() {
		t.OriginalIssuedAt = t.IssuedAt
	}
	s.tokens[t.ID] = t
	heap.Push(s.pq, t)
}

// Get returns a token by id (nil if absent or already revoked).
func (s *Store) Get(id string) *models.IssuedToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t := s.tokens[id]
	if t == nil || t.Revoked {
		return nil
	}
	return t
}

// List returns a snapshot of all currently-live tokens.
func (s *Store) List() []*models.IssuedToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*models.IssuedToken, 0, len(s.tokens))
	for _, t := range s.tokens {
		if !t.Revoked {
			out = append(out, t)
		}
	}
	return out
}

// RevokeNow manually revokes a token (used by the CLI revoke subcommand and
// tests). Idempotent. Uses the retry revoker when configured.
func (s *Store) RevokeNow(ctx context.Context, id string) error {
	s.mu.Lock()
	t, ok := s.tokens[id]
	if !ok || t.Revoked {
		s.mu.Unlock()
		return nil
	}
	t.Revoked = true
	s.revokedCount++
	revoker := s.revoker
	issuer := s.issuer
	auditLog := s.auditLog
	s.mu.Unlock()

	if revoker != nil {
		if err := revoker.Revoke(ctx, t); err != nil {
			return err
		}
	} else if issuer != nil {
		if err := issuer.Revoke(ctx, t); err != nil {
			return err
		}
	}
	if auditLog != nil {
		auditLog.LogRevoked(t, "manual")
	}
	return nil
}

// RevokedCount returns the number of tokens revoked (auto + manual).
func (s *Store) RevokedCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.revokedCount
}

// Extend attempts to renew a token's TTL by the configured amount, subject to:
//  1. The token must exist and not be revoked.
//  2. The new ExpiresAt must not exceed OriginalIssuedAt + maxSession.
//
// It does NOT re-validate the operational context here — that is done by the
// caller (the API handler invokes the auth Engine before calling Extend).
func (s *Store) Extend(ctx context.Context, id string) ExtendResult {
	s.mu.Lock()
	t, ok := s.tokens[id]
	if !ok || t.Revoked {
		s.mu.Unlock()
		return ExtendResult{Extended: false, Reason: "token not found or already revoked"}
	}

	now := time.Now()
	newExpiry := t.ExpiresAt.Add(s.ttl)
	maxSessionAt := t.OriginalIssuedAt.Add(s.maxSession)

	// If the new expiry would reach or exceed the session ceiling, clamp or revoke.
	if !newExpiry.Before(maxSessionAt) {
		// Clamp to the ceiling and revoke immediately
		clampedExpiry := maxSessionAt
		if now.After(clampedExpiry) || now.Equal(clampedExpiry) {
			t.Revoked = true
			s.revokedCount++
			issuer := s.issuer
			s.mu.Unlock()
			if issuer != nil {
				_ = issuer.Revoke(ctx, t)
			}
			return ExtendResult{
				Extended:     false,
				Token:        t,
				MaxSessionAt: maxSessionAt,
				Reason:       "session ceiling reached — token forcibly revoked",
			}
		}
		// Clamp the expiry to the ceiling
		newExpiry = clampedExpiry
		t.ExpiresAt = newExpiry
		t.ExtensionCount++
		// Reset the notified flag so a second warning can fire in the new window
		t.NotifiedExpiry = false
		extensionsLeft := 0
		issuer := s.issuer
		s.mu.Unlock()
		// Re-issue the token at the provider to extend its real TTL
		if issuer != nil {
			newTok, err := issuer.Issue(ctx, t.User, t.Resource, time.Until(newExpiry))
			if err != nil {
				return ExtendResult{Extended: false, Reason: err.Error()}
			}
			// Update the token value in the store
			s.mu.Lock()
			if cur, ok := s.tokens[id]; ok {
				cur.Token = newTok.Token
			}
			s.mu.Unlock()
		}
		return ExtendResult{
			Extended:       true,
			Token:          t,
			NewExpiresAt:   newExpiry,
			MaxSessionAt:   maxSessionAt,
			ExtensionsLeft: extensionsLeft,
		}
	}

	// Normal extension
	t.ExpiresAt = newExpiry
	t.ExtensionCount++
	t.NotifiedExpiry = false
	extensionsUsed := t.ExtensionCount
	extensionsLeft := s.maxExtensionsForCeiling(t, now)
	issuer := s.issuer
	s.mu.Unlock()

	// Re-issue the token at the provider to extend its real TTL
	if issuer != nil {
		newTok, err := issuer.Issue(ctx, t.User, t.Resource, s.ttl)
		if err != nil {
			return ExtendResult{Extended: false, Reason: err.Error()}
		}
		// Update the token value in the store
		s.mu.Lock()
		if cur, ok := s.tokens[id]; ok {
			cur.Token = newTok.Token
		}
		s.mu.Unlock()
	}

	_ = extensionsUsed
	return ExtendResult{
		Extended:       true,
		Token:          t,
		NewExpiresAt:   newExpiry,
		MaxSessionAt:   maxSessionAt,
		ExtensionsLeft: extensionsLeft,
	}
}

// maxExtensionsForCeiling estimates how many more full-TTL extensions can
// fit before hitting the session ceiling.
func (s *Store) maxExtensionsForCeiling(t *models.IssuedToken, now time.Time) int {
	maxSessionAt := t.OriginalIssuedAt.Add(s.maxSession)
	remaining := time.Until(maxSessionAt)
	if remaining <= 0 {
		return 0
	}
	return int(remaining / s.ttl)
}

// Run is the self-destruction worker. It blocks until ctx is cancelled. On
// each tick it:
//  1. Fires warning notifications for tokens nearing expiry.
//  2. Pops every heap element whose ExpiresAt <= now and revokes it.
func (s *Store) Run(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.fireWarnings(ctx, now)
			s.revokeExpired(ctx, now)
		}
	}
}

// fireWarnings checks all live tokens and sends an "impending expiration"
// notification to any token whose remaining TTL has dropped below the
// warning window for the first time.
func (s *Store) fireWarnings(ctx context.Context, now time.Time) {
	s.mu.Lock()
	var toNotify []*models.IssuedToken
	for _, t := range s.tokens {
		if t.Revoked || t.NotifiedExpiry {
			continue
		}
		timeLeft := t.ExpiresAt.Sub(now)
		if timeLeft <= s.warningBefore && timeLeft > 0 {
			t.NotifiedExpiry = true
			toNotify = append(toNotify, t)
		}
	}
	warnedCh := s.warnedChan
	n := s.notifier
	s.mu.Unlock()

	for _, t := range toNotify {
		timeLeft := t.ExpiresAt.Sub(now)
		if n != nil {
			if err := n.NotifyExpiring(ctx, t, timeLeft); err != nil {
				log.Printf("store: warning notification for %s failed: %v", t.ID, err)
			}
		}
		if warnedCh != nil {
			warnedCh <- t.ID
		}
	}
}

// revokeExpired pops all heap entries whose expiry has passed and revokes them.
// Uses the retry revoker when configured for resilient revocation.
func (s *Store) revokeExpired(ctx context.Context, now time.Time) {
	for {
		s.mu.Lock()
		if s.pq.Len() == 0 {
			s.mu.Unlock()
			return
		}
		top := (*s.pq)[0]
		if top.ExpiresAt.After(now) {
			// earliest unexpired — stop scanning
			s.mu.Unlock()
			return
		}
		heap.Pop(s.pq)
		t, ok := s.tokens[top.ID]
		if !ok || t.Revoked {
			s.mu.Unlock()
			continue
		}
		t.Revoked = true
		s.revokedCount++
		ch := s.revokedChan
		revoker := s.revoker
		issuer := s.issuer
		auditLog := s.auditLog
		s.mu.Unlock()

		if revoker != nil {
			if err := revoker.Revoke(ctx, t); err != nil {
				log.Printf("store: revoke %s failed after retries: %v", t.ID, err)
			}
		} else if issuer != nil {
			if err := issuer.Revoke(ctx, t); err != nil {
				log.Printf("store: revoke %s failed: %v", t.ID, err)
			}
		}
		if auditLog != nil {
			auditLog.LogRevoked(t, "auto")
		}
		if ch != nil {
			ch <- t.ID
		}
	}
}

// --- min-heap ordered by ExpiresAt ---

type tokenHeap []*models.IssuedToken

func (h tokenHeap) Len() int           { return len(h) }
func (h tokenHeap) Less(i, j int) bool { return h[i].ExpiresAt.Before(h[j].ExpiresAt) }
func (h tokenHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *tokenHeap) Push(x any) {
	*h = append(*h, x.(*models.IssuedToken))
}

func (h *tokenHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}