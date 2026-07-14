package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/example/jit-access-broker/audit"
	"github.com/example/jit-access-broker/models"
	"github.com/example/jit-access-broker/persistence"
	"github.com/example/jit-access-broker/providers"
	"github.com/example/jit-access-broker/retry"
	"github.com/example/jit-access-broker/store"
)

// makeToken is a test helper that creates a valid models.IssuedToken.
func makeToken(user, resource string, ttl time.Duration) *models.IssuedToken {
	now := time.Now().UTC()
	return &models.IssuedToken{
		ID:               "tok_" + user + "_" + resource,
		User:             user,
		Resource:         resource,
		Token:            "demo-token-" + user,
		IssuedAt:         now,
		OriginalIssuedAt: now,
		ExpiresAt:        now.Add(ttl),
		Provider:         "demo",
	}
}

// ===== AUDIT TESTS =====

func TestAuditEmit(t *testing.T) {
	var buf bytes.Buffer
	logger := audit.NewLoggerWith(&buf)

	logger.Emit(audit.Event{
		EventType: "test.event",
		Actor:     "alice",
		Resource:  "prod-db",
		Outcome:   audit.OutcomeSuccess,
	})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}

	var event audit.Event
	if err := json.Unmarshal([]byte(lines[0]), &event); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if event.Actor != "alice" {
		t.Errorf("actor = %s, want alice", event.Actor)
	}
	if event.Timestamp == "" {
		t.Error("expected non-empty timestamp")
	}
}

func TestAuditLogGranted(t *testing.T) {
	var buf bytes.Buffer
	logger := audit.NewLoggerWith(&buf)

	tok := makeToken("bob", "vault", 60*time.Minute)
	logger.LogGranted(tok, 3600)

	var event audit.Event
	if err := json.Unmarshal(buf.Bytes(), &event); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if event.EventType != audit.EventGranted {
		t.Errorf("event_type = %s, want %s", event.EventType, audit.EventGranted)
	}
	if event.Outcome != audit.OutcomeSuccess {
		t.Errorf("outcome = %s, want success", event.Outcome)
	}
}

func TestAuditLogRevoked(t *testing.T) {
	var buf bytes.Buffer
	logger := audit.NewLoggerWith(&buf)

	tok := makeToken("carol", "aws", 30*time.Minute)
	logger.LogRevoked(tok, "auto")

	var event audit.Event
	if err := json.Unmarshal(buf.Bytes(), &event); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if event.EventType != audit.EventRevoked {
		t.Errorf("event_type = %s", event.EventType)
	}
	if event.Metadata["source"] != "auto" {
		t.Errorf("source = %v", event.Metadata["source"])
	}
}

// ===== RETRY TESTS =====

func TestRetryRevokeSuccess(t *testing.T) {
	issuer := &providers.DemoIssuer{}
	revoker := retry.NewRetryRevoker(issuer, nil)

	tok := makeToken("alice", "vault", 5*time.Minute)
	if err := revoker.Revoke(context.Background(), tok); err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestRetryLogsFailures(t *testing.T) {
	var buf bytes.Buffer
	logger := audit.NewLoggerWith(&buf)

	issuer := &alwaysFailIssuer{}
	revoker := retry.NewRetryRevoker(issuer, logger)
	revoker.BaseDelay = 1 * time.Millisecond
	revoker.MaxDelay = 1 * time.Millisecond
	revoker.MaxAttempts = 3
	revoker.SetSleeper(func(d time.Duration) {})

	tok := makeToken("bob", "vault", 5*time.Minute)
	_ = revoker.Revoke(context.Background(), tok)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 audit lines (one per failure), got %d", len(lines))
	}
	for i, line := range lines {
		var event audit.Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("line %d invalid JSON: %v", i, err)
		}
		if event.EventType != audit.EventRevokeFailed {
			t.Errorf("line %d event_type = %s, want %s", i, event.EventType, audit.EventRevokeFailed)
		}
	}
}

func TestRetryRevokeAllFailures(t *testing.T) {
	issuer := &alwaysFailIssuer{}
	revoker := retry.NewRetryRevoker(issuer, nil)
	revoker.BaseDelay = 1 * time.Millisecond
	revoker.MaxDelay = 2 * time.Millisecond
	revoker.MaxAttempts = 3
	revoker.SetSleeper(func(d time.Duration) {})

	tok := makeToken("bob", "vault", 5*time.Minute)
	err := revoker.Revoke(context.Background(), tok)
	if err == nil {
		t.Error("expected error after all attempts exhausted")
	}
}

// alwaysFailIssuer always fails Revoke.
type alwaysFailIssuer struct{ providers.DemoIssuer }

func (a *alwaysFailIssuer) Revoke(ctx context.Context, t *models.IssuedToken) error {
	return errSimulated
}

var errSimulated = &simErr{}

type simErr struct{}

func (e *simErr) Error() string { return "simulated revocation failure" }

// ===== PERSISTENCE TESTS =====

func TestPersistenceSaveLoad(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "state.json")
	ps := persistence.New(path)

	tok1 := makeToken("alice", "vault", 60*time.Minute)
	tok2 := makeToken("bob", "aws", 30*time.Minute)

	records := []persistence.Record{
		persistence.ToRecord(tok1),
		persistence.ToRecord(tok2),
	}

	if err := ps.SaveAll(records); err != nil {
		t.Fatalf("SaveAll: %v", err)
	}

	loaded, err := ps.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("loaded %d records, want 2", len(loaded))
	}
	if loaded[0].ID != tok1.ID {
		t.Errorf("record[0].ID = %s, want %s", loaded[0].ID, tok1.ID)
	}
}

func TestPersistenceLoadEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "nonexistent.json")
	ps := persistence.New(path)

	records, err := ps.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll on missing file: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("expected 0 records, got %d", len(records))
	}
}

func TestPersistenceLoadActive(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "state.json")
	ps := persistence.New(path)

	tok1 := makeToken("alice", "vault", 60*time.Minute)
	tok2 := makeToken("bob", "aws", 30*time.Minute)
	tok2.Revoked = true

	_ = ps.SaveAll([]persistence.Record{
		persistence.ToRecord(tok1),
		persistence.ToRecord(tok2),
	})

	active, err := ps.LoadActive()
	if err != nil {
		t.Fatalf("LoadActive: %v", err)
	}
	if len(active) != 1 {
		t.Fatalf("active = %d, want 1", len(active))
	}
	if active[0].ID != tok1.ID {
		t.Errorf("active[0].ID = %s, want %s", active[0].ID, tok1.ID)
	}
}

func TestMissedExpirations(t *testing.T) {
	now := time.Now()
	records := []persistence.Record{
		{ID: "t1", ExpiresAt: now.Add(-1 * time.Hour), Revoked: false},
		{ID: "t2", ExpiresAt: now.Add(30 * time.Minute), Revoked: false},
		{ID: "t3", ExpiresAt: now.Add(-5 * time.Minute), Revoked: true},
	}

	missed := persistence.MissedExpirations(records, now)
	if len(missed) != 1 {
		t.Fatalf("missed = %d, want 1", len(missed))
	}
	if missed[0].ID != "t1" {
		t.Errorf("missed[0].ID = %s, want t1", missed[0].ID)
	}
}

// ===== STORE + PERSISTENCE INTEGRATION =====

func TestStoreRecoveryRestoresLiveTokens(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "state.json")

	ps1 := persistence.New(path)
	tok1 := makeToken("alice", "vault", 60*time.Minute)
	tok2 := makeToken("bob", "aws", 60*time.Minute)

	_ = ps1.SaveAll([]persistence.Record{
		persistence.ToRecord(tok1),
		persistence.ToRecord(tok2),
	})

	issuer := &providers.DemoIssuer{}
	st := store.New(issuer)
	ps2 := persistence.New(path)
	if err := st.SetPersistence(ps2); err != nil {
		t.Fatalf("SetPersistence: %v", err)
	}

	live := st.List()
	if len(live) != 2 {
		t.Errorf("live tokens = %d, want 2", len(live))
	}
}

func TestStoreRecoveryRevokesMissed(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "state.json")

	ps1 := persistence.New(path)
	expiredTok := makeToken("alice", "vault", -1*time.Hour)
	expiredTok.ExpiresAt = time.Now().Add(-1 * time.Hour)

	_ = ps1.SaveAll([]persistence.Record{
		persistence.ToRecord(expiredTok),
	})

	issuer := &providers.DemoIssuer{}
	st := store.New(issuer)
	ps2 := persistence.New(path)
	_ = st.SetPersistence(ps2)

	if st.RevokedCount() != 1 {
		t.Errorf("revokedCount = %d, want 1", st.RevokedCount())
	}
}

func TestStorePersistAll(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "state.json")

	issuer := &providers.DemoIssuer{}
	st := store.New(issuer)
	ps := persistence.New(path)

	tok := makeToken("alice", "vault", 60*time.Minute)
	st.Add(tok)

	_ = st.SetPersistence(ps)
	if err := st.PersistAll(); err != nil {
		t.Fatalf("PersistAll: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) == 0 {
		t.Error("persistence file is empty")
	}
}

// ===== STORE + AUDIT/RETRY INTEGRATION =====

func TestStoreAuditLogging(t *testing.T) {
	var buf bytes.Buffer
	logger := audit.NewLoggerWith(&buf)

	issuer := &providers.DemoIssuer{}
	st := store.New(issuer)
	st.SetAuditLogger(logger)

	tok := makeToken("alice", "vault", 60*time.Minute)
	st.Add(tok)

	_ = st.RevokeNow(context.Background(), tok.ID)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) == 0 {
		t.Fatal("expected at least 1 audit line from revoke")
	}
	var event audit.Event
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &event); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if event.EventType != audit.EventRevoked {
		t.Errorf("event_type = %s, want %s", event.EventType, audit.EventRevoked)
	}
}

func TestStoreRetryRevoker(t *testing.T) {
	issuer := &providers.DemoIssuer{}
	logger := audit.NewLogger()
	revoker := retry.NewRetryRevoker(issuer, logger)
	revoker.SetSleeper(func(d time.Duration) {})

	st := store.New(issuer)
	st.SetRetryRevoker(revoker)

	tok := makeToken("alice", "vault", 60*time.Minute)
	st.Add(tok)

	if err := st.RevokeNow(context.Background(), tok.ID); err != nil {
		t.Errorf("RevokeNow with retry: %v", err)
	}
}