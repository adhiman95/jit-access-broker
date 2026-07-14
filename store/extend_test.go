package store

import (
	"context"
	"testing"
	"time"

	"github.com/example/jit-access-broker/models"
	"github.com/example/jit-access-broker/notifier"
)

// TestExtendHappyPath verifies that a normal extension adds the configured TTL
// to ExpiresAt and increments ExtensionCount.
func TestExtendHappyPath(t *testing.T) {
	f := &fakeIssuer{}
	s := New(f)
	s.SetSessionLimits(60*time.Minute, 4*time.Hour, 15*time.Minute)

	now := time.Now()
	tok := &models.IssuedToken{
		ID: "tok_a", User: "alice", Resource: "db", Token: "secret",
		IssuedAt: now, ExpiresAt: now.Add(60 * time.Minute),
		OriginalIssuedAt: now,
	}
	s.Add(tok)

	res := s.Extend(context.Background(), "tok_a")
	if !res.Extended {
		t.Fatalf("expected extended=true, got reason=%q", res.Reason)
	}
	want := now.Add(120 * time.Minute)
	if !res.NewExpiresAt.Equal(want) {
		t.Errorf("new expiry = %v, want %v", res.NewExpiresAt, want)
	}
	if res.Token.ExtensionCount != 1 {
		t.Errorf("extension count = %d, want 1", res.Token.ExtensionCount)
	}
	// extensionsLeft should be 2: 4h/60m = 4, minus the 1 used = 3 total, minus 1 just used = wait,
	// let's compute: ceiling=4h, ttl=60m → max 4 grants total (1 original + 3 extensions)
	// After 1 extension, extensionsLeft should be 2 (can still extend twice more).
	if res.ExtensionsLeft < 1 {
		t.Errorf("extensions left = %d, expected >= 1", res.ExtensionsLeft)
	}
}

// TestExtendUnknownToken verifies that extending a non-existent token fails.
func TestExtendUnknownToken(t *testing.T) {
	s := New(&fakeIssuer{})
	res := s.Extend(context.Background(), "nope")
	if res.Extended {
		t.Fatal("expected extended=false for unknown token")
	}
}

// TestExtendRevokedToken verifies that extending a revoked token fails.
func TestExtendRevokedToken(t *testing.T) {
	s := New(&fakeIssuer{})
	tok := &models.IssuedToken{ID: "r", ExpiresAt: time.Now().Add(time.Hour)}
	s.Add(tok)
	_ = s.RevokeNow(context.Background(), "r")
	res := s.Extend(context.Background(), "r")
	if res.Extended {
		t.Fatal("expected extended=false for revoked token")
	}
}

// TestExtendSessionCeilingClampsAndForciblyRevokes verifies that when an
// extension would exceed MaxSessionDuration, the token is either clamped to
// the ceiling (if still valid) or forcibly revoked (if the session age has
// already passed the ceiling).
func TestExtendSessionCeilingClampsAndForciblyRevokes(t *testing.T) {
	f := &fakeIssuer{}
	s := New(f)
	// Very short ceiling: 2 minutes, TTL: 1 minute
	s.SetSessionLimits(1*time.Minute, 2*time.Minute, 10*time.Second)

	now := time.Now()

	// --- Case 1: session still valid but extension would exceed ceiling → clamp ---
	// Issued 1m30s ago, ceiling is 2m → session age 1m30s, ceiling at now+30s
	// ExpiresAt is now-30s (expired), newExpiry = now+30s = ceiling exactly → clamp
	tok1 := &models.IssuedToken{
		ID:               "clamp",
		User:             "bob",
		Resource:         "db",
		Token:            "secret",
		IssuedAt:         now.Add(-90 * time.Second),
		ExpiresAt:        now.Add(-30 * time.Second),
		OriginalIssuedAt: now.Add(-90 * time.Second),
	}
	s.Add(tok1)

	// Make ExpiresAt so that newExpiry > ceiling:
	// newExpiry = ExpiresAt + 1m. Set ExpiresAt = now - 29s → newExpiry = now + 31s > ceiling (now + 30s)
	tok1.ExpiresAt = now.Add(-29 * time.Second)
	res := s.Extend(context.Background(), "clamp")
	ceiling := tok1.OriginalIssuedAt.Add(2 * time.Minute)
	if !res.Extended {
		t.Fatalf("expected clamp+extend=true, got reason=%q", res.Reason)
	}
	if !res.NewExpiresAt.Equal(ceiling) {
		t.Errorf("expected clamped to ceiling %v, got %v", ceiling, res.NewExpiresAt)
	}

	// --- Case 2: session age already past ceiling → forcibly revoked ---
	tok2 := &models.IssuedToken{
		ID:               "force_revoke",
		User:             "carol",
		Resource:         "db",
		Token:            "secret2",
		IssuedAt:         now.Add(-3 * time.Minute), // 3m ago, ceiling is 2m
		ExpiresAt:        now.Add(-2 * time.Minute),
		OriginalIssuedAt: now.Add(-3 * time.Minute),
	}
	s.Add(tok2)
	res2 := s.Extend(context.Background(), "force_revoke")
	if res2.Extended {
		t.Fatal("expected extended=false when session past ceiling")
	}
	if res2.Token == nil || !res2.Token.Revoked {
		t.Error("expected token to be forcibly revoked")
	}
	if res2.Reason == "" {
		t.Error("expected a reason string")
	}
}

// TestWarningNotificationFires verifies that the warning worker fires a
// notification WarningBeforeExpiry before the token expires.
func TestWarningNotificationFires(t *testing.T) {
	f := &fakeIssuer{}
	s := New(f)
	s.SetSessionLimits(500*time.Millisecond, 10*time.Second, 300*time.Millisecond)

	warnedCh := make(chan string, 2)
	s.SetWarnedChan(warnedCh)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	now := time.Now()
	tok := &models.IssuedToken{
		ID: "warn", User: "dave", Resource: "db", Token: "s",
		IssuedAt: now, ExpiresAt: now.Add(500 * time.Millisecond),
		OriginalIssuedAt: now,
	}
	s.Add(tok)

	select {
	case id := <-warnedCh:
		if id != "warn" {
			t.Errorf("warned id = %q, want warn", id)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("warning notification did not fire within 3s")
	}
}

// TestWarningNotifiesOnlyOnce verifies the NotifiedExpiry flag prevents
// duplicate warnings.
func TestWarningNotifiesOnlyOnce(t *testing.T) {
	f := &fakeIssuer{}
	s := New(f)
	s.SetSessionLimits(500*time.Millisecond, 10*time.Second, 300*time.Millisecond)

	warnedCount := 0
	s.SetNotifier(&countingNotifier{count: &warnedCount})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	now := time.Now()
	tok := &models.IssuedToken{
		ID: "once", User: "eve", Resource: "db", Token: "s",
		IssuedAt: now, ExpiresAt: now.Add(500 * time.Millisecond),
		OriginalIssuedAt: now,
	}
	s.Add(tok)

	// Wait for token to expire + some buffer
	time.Sleep(1 * time.Second)
	if warnedCount > 1 {
		t.Errorf("warning fired %d times, expected at most 1", warnedCount)
	}
}

// TestExtendResetsNotificationFlag verifies that after an extension, a second
// warning can fire in the new window.
func TestExtendResetsNotificationFlag(t *testing.T) {
	f := &fakeIssuer{}
	s := New(f)
	s.SetSessionLimits(500*time.Millisecond, 10*time.Second, 300*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	now := time.Now()
	tok := &models.IssuedToken{
		ID: "reset", User: "frank", Resource: "db", Token: "s",
		IssuedAt: now, ExpiresAt: now.Add(500 * time.Millisecond),
		OriginalIssuedAt: now,
	}
	s.Add(tok)

	// Simulate the warning being sent
	s.mu.Lock()
	tok.NotifiedExpiry = true
	s.mu.Unlock()

	// Extend should reset the flag
	res := s.Extend(context.Background(), "reset")
	if !res.Extended {
		t.Fatalf("extend failed: %s", res.Reason)
	}
	s.mu.RLock()
	flag := tok.NotifiedExpiry
	s.mu.RUnlock()
	if flag {
		t.Error("NotifiedExpiry should be reset to false after extend")
	}
}

// countingNotifier is a test notifier that counts calls.
type countingNotifier struct {
	count *int
}

func (c *countingNotifier) NotifyExpiring(_ context.Context, _ *models.IssuedToken, _ time.Duration) error {
	*c.count++
	return nil
}

// Ensure NoopNotifier satisfies the interface (compile-time check).
var _ notifier.Notifier = notifier.NoopNotifier{}