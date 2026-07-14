package store

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/example/jit-access-broker/models"
)

// fakeIssuer records every Issue + Revoke for assertions.
type fakeIssuer struct {
	issued  int32
	revoked int32
	lastTok *models.IssuedToken
}

func (f *fakeIssuer) Issue(ctx context.Context, user, resource string, ttl time.Duration) (*models.IssuedToken, error) {
	atomic.AddInt32(&f.issued, 1)
	now := time.Now().UTC()
	t := &models.IssuedToken{
		ID: "tok_" + user, User: user, Resource: resource,
		Token: "secret-" + user, IssuedAt: now, ExpiresAt: now.Add(ttl), Provider: "fake",
	}
	f.lastTok = t
	return t, nil
}

func (f *fakeIssuer) Revoke(ctx context.Context, t *models.IssuedToken) error {
	atomic.AddInt32(&f.revoked, 1)
	return nil
}

func (f *fakeIssuer) Name() string { return "fake" }

func TestHeapOrderingByExpiry(t *testing.T) {
	now := time.Now()
	tokens := []*models.IssuedToken{
		{ID: "a", ExpiresAt: now.Add(30 * time.Second)},
		{ID: "b", ExpiresAt: now.Add(5 * time.Second)},  // earliest
		{ID: "c", ExpiresAt: now.Add(15 * time.Second)},
		{ID: "d", ExpiresAt: now.Add(60 * time.Second)}, // latest
	}
	s := New(nil)
	for _, tk := range tokens {
		s.Add(tk)
	}
	if s.pq.Len() != 4 {
		t.Fatalf("heap len = %d, want 4", s.pq.Len())
	}
	if (*s.pq)[0].ID != "b" {
		t.Errorf("heap root = %q, want b (earliest)", (*s.pq)[0].ID)
	}
}

func TestAutoRevocationFiresAtExpiry(t *testing.T) {
	f := &fakeIssuer{}
	s := New(f)
	ch := make(chan string, 4)
	s.SetRevokedChan(ch)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	// Issue a token with a 300ms TTL.
	tok, _ := f.Issue(ctx, "alice", "db", 300*time.Millisecond)
	s.Add(tok)

	select {
	case id := <-ch:
		if id != tok.ID {
			t.Errorf("revoked id = %q, want %q", id, tok.ID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("auto-revocation did not fire within 3s")
	}
	if s.RevokedCount() != 1 {
		t.Errorf("revoked count = %d, want 1", s.RevokedCount())
	}
	if atomic.LoadInt32(&f.revoked) != 1 {
		t.Errorf("issuer revoked calls = %d, want 1", f.revoked)
	}
	if s.Get(tok.ID) != nil {
		t.Error("token should be gone after revoke")
	}
}

func TestManualRevokeNow(t *testing.T) {
	f := &fakeIssuer{}
	s := New(f)
	now := time.Now()
	tok := &models.IssuedToken{ID: "x", User: "u", Token: "t", ExpiresAt: now.Add(time.Hour)}
	s.Add(tok)

	if err := s.RevokeNow(context.Background(), "x"); err != nil {
		t.Fatalf("revoke now failed: %v", err)
	}
	if s.Get("x") != nil {
		t.Fatal("token still present after manual revoke")
	}
	if s.RevokedCount() != 1 {
		t.Errorf("revoked count = %d, want 1", s.RevokedCount())
	}
	// idempotent
	if err := s.RevokeNow(context.Background(), "x"); err != nil {
		t.Errorf("idempotent revoke failed: %v", err)
	}
}

func TestListOnlyLive(t *testing.T) {
	s := New(nil)
	now := time.Now()
	live := &models.IssuedToken{ID: "l", ExpiresAt: now.Add(time.Hour)}
	dead := &models.IssuedToken{ID: "d", ExpiresAt: now.Add(time.Hour), Revoked: true}
	s.Add(live)
	s.tokens["d"] = dead // direct insert to simulate already-revoked
	list := s.List()
	if len(list) != 1 || list[0].ID != "l" {
		t.Errorf("list = %+v, want only [l]", list)
	}
}

func TestMultipleTokensRevokedInOrder(t *testing.T) {
	f := &fakeIssuer{}
	s := New(f)
	ch := make(chan string, 4)
	s.SetRevokedChan(ch)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	// t1 expires earliest despite t2 being added first.
	t1, _ := f.Issue(ctx, "u1", "r", 200*time.Millisecond)
	t2, _ := f.Issue(ctx, "u2", "r", 600*time.Millisecond)
	s.Add(t2)
	s.Add(t1)

	var order []string
	for i := 0; i < 2; i++ {
		select {
		case id := <-ch:
			order = append(order, id)
		case <-time.After(4 * time.Second):
			t.Fatalf("timeout waiting for revoke %d", i)
		}
	}
	if len(order) != 2 || order[0] != t1.ID || order[1] != t2.ID {
		t.Errorf("revocation order = %v, want [%s, %s]", order, t1.ID, t2.ID)
	}
}