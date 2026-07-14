package breakglass

import (
	"context"
	"testing"
	"time"

	"github.com/example/jit-access-broker/audit"
	"github.com/example/jit-access-broker/providers"
)

// TestGenerateAndVerifyKeyPair ensures key generation produces valid Ed25519 keys.
func TestGenerateAndVerifyKeyPair(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if pub == "" || priv == "" {
		t.Fatal("empty keys returned")
	}
	if len(pub) != 64 { // 32 bytes hex = 64 chars
		t.Errorf("public key hex length = %d, want 64", len(pub))
	}
	if len(priv) != 128 { // 64 bytes hex = 128 chars
		t.Errorf("private key hex length = %d, want 128", len(priv))
	}
}

// TestSignAndVerifyMessage ensures a signature from a generated key verifies correctly.
func TestSignAndVerifyMessage(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	req := BreakGlassRequest{
		User:       "alice@example.com",
		Resource:   "prod-db",
		Reason:     "outage debugging",
		TTLMinutes: 30,
	}

	sig, err := SignMessage(priv, req)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	if sig == "" {
		t.Fatal("empty signature")
	}

	// Verify using a Manager wired with this public key
	mgr := NewManager(map[string]string{"approver1": pub}, &providers.DemoIssuer{}, audit.NewLogger())

	ok, reason, approvers, err := mgr.Verify(BreakGlassRequest{
		User:       "alice@example.com",
		Resource:   "prod-db",
		Reason:     "outage debugging",
		TTLMinutes: 30,
		Signatures: []ApprovalSignature{
			{ApproverID: "approver1", Signature: sig},
		},
	})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	// Only 1 signature — quorum not met (needs 2)
	if ok {
		t.Error("expected quorum failure with 1 signature")
	}
	if reason == "" {
		t.Error("expected non-empty rejection reason")
	}
	if len(approvers) != 0 {
		t.Errorf("approvers = %d, want 0 (quorum not met)", len(approvers))
	}
}

// TestQuorumMet verifies that 2 valid distinct signatures pass quorum.
func TestQuorumMet(t *testing.T) {
	pub1, priv1, _ := GenerateKeyPair()
	pub2, priv2, _ := GenerateKeyPair()

	approvers := map[string]string{
		"alice": pub1,
		"bob":   pub2,
	}
	mgr := NewManager(approvers, &providers.DemoIssuer{}, audit.NewLogger())

	req := BreakGlassRequest{
		User:       "carol@example.com",
		Resource:   "prod-k8s",
		Reason:     "pod crashloop",
		TTLMinutes: 45,
	}

	sig1, _ := SignMessage(priv1, req)
	sig2, _ := SignMessage(priv2, req)
	req.Signatures = []ApprovalSignature{
		{ApproverID: "alice", Signature: sig1},
		{ApproverID: "bob", Signature: sig2},
	}

	ok, reason, approverList, err := mgr.Verify(req)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if !ok {
		t.Errorf("expected quorum success, got rejection: %s", reason)
	}
	if len(approverList) != 2 {
		t.Errorf("approver count = %d, want 2", len(approverList))
	}
}

// TestQuorumInsufficient ensures 1 signature is rejected.
func TestQuorumInsufficient(t *testing.T) {
	pub1, priv1, _ := GenerateKeyPair()
	mgr := NewManager(map[string]string{"alice": pub1}, &providers.DemoIssuer{}, nil)

	req := BreakGlassRequest{
		User:       "carol@example.com",
		Resource:   "prod-db",
		Reason:     "test",
		TTLMinutes: 30,
	}
	sig1, _ := SignMessage(priv1, req)
	req.Signatures = []ApprovalSignature{
		{ApproverID: "alice", Signature: sig1},
	}

	ok, reason, _, _ := mgr.Verify(req)
	if ok {
		t.Error("expected rejection with 1 signature")
	}
	if reason == "" {
		t.Error("expected non-empty rejection reason")
	}
}

// TestInvalidSignatureRejected ensures tampered signatures are rejected.
func TestInvalidSignatureRejected(t *testing.T) {
	pub1, _, _ := GenerateKeyPair()
	pub2, priv2, _ := GenerateKeyPair()

	mgr := NewManager(map[string]string{"alice": pub1, "bob": pub2}, &providers.DemoIssuer{}, nil)

	req := BreakGlassRequest{
		User:       "carol@example.com",
		Resource:   "prod-db",
		Reason:     "test",
		TTLMinutes: 30,
	}

	// bob signs a DIFFERENT message (tampered reason)
	sig2, _ := SignMessage(priv2, BreakGlassRequest{
		User: "carol@example.com", Resource: "prod-db", Reason: "WRONG", TTLMinutes: 30,
	})

	// alice's signature is garbage hex
	req.Signatures = []ApprovalSignature{
		{ApproverID: "alice", Signature: "deadbeef"},
		{ApproverID: "bob", Signature: sig2},
	}

	ok, _, _, _ := mgr.Verify(req)
	if ok {
		t.Error("expected rejection with invalid signatures")
	}
}

// TestDuplicateApproverRejected ensures the same approver signing twice doesn't count as 2.
func TestDuplicateApproverRejected(t *testing.T) {
	pub1, priv1, _ := GenerateKeyPair()
	mgr := NewManager(map[string]string{"alice": pub1}, &providers.DemoIssuer{}, nil)

	req := BreakGlassRequest{
		User:       "carol@example.com",
		Resource:   "prod-db",
		Reason:     "test",
		TTLMinutes: 30,
	}
	sig1, _ := SignMessage(priv1, req)

	// Same approver signs twice
	req.Signatures = []ApprovalSignature{
		{ApproverID: "alice", Signature: sig1},
		{ApproverID: "alice", Signature: sig1},
	}

	ok, _, approverList, _ := mgr.Verify(req)
	if ok {
		t.Error("expected rejection — duplicate approver should not count as quorum")
	}
	if len(approverList) != 1 {
		t.Errorf("approverList = %d, want 1 (deduped)", len(approverList))
	}
}

// TestUnknownApproverIgnored ensures untrusted approver IDs are silently ignored.
func TestUnknownApproverIgnored(t *testing.T) {
	pub1, priv1, _ := GenerateKeyPair()
	_, priv2, _ := GenerateKeyPair() // untrusted keypair; pub2 deliberately unused

	// Only alice is trusted
	mgr := NewManager(map[string]string{"alice": pub1}, &providers.DemoIssuer{}, nil)

	req := BreakGlassRequest{
		User:       "carol@example.com",
		Resource:   "prod-db",
		Reason:     "test",
		TTLMinutes: 30,
	}
	sig1, _ := SignMessage(priv1, req)
	sig2, _ := SignMessage(priv2, req)

	req.Signatures = []ApprovalSignature{
		{ApproverID: "alice", Signature: sig1},
		{ApproverID: "mallory", Signature: sig2}, // unknown approver
	}

	ok, _, _, _ := mgr.Verify(req)
	if ok {
		t.Error("expected rejection — unknown approver should not satisfy quorum")
	}
}

// TestActivateSuccess verifies full end-to-end activation issues a token.
func TestActivateSuccess(t *testing.T) {
	pub1, priv1, _ := GenerateKeyPair()
	pub2, priv2, _ := GenerateKeyPair()

	mgr := NewManager(map[string]string{
		"alice": pub1,
		"bob":   pub2,
	}, &providers.DemoIssuer{}, audit.NewLogger())

	req := BreakGlassRequest{
		User:       "carol@example.com",
		Resource:   "prod-vault",
		Reason:     "seal failure",
		TTLMinutes: 30,
	}
	sig1, _ := SignMessage(priv1, req)
	sig2, _ := SignMessage(priv2, req)
	req.Signatures = []ApprovalSignature{
		{ApproverID: "alice", Signature: sig1},
		{ApproverID: "bob", Signature: sig2},
	}

	tok, reason, err := mgr.Activate(context.Background(), req)
	if err != nil {
		t.Fatalf("Activate error: %v", err)
	}
	if tok == nil {
		t.Fatalf("expected token, got nil: %s", reason)
	}
	if tok.User != "carol@example.com" {
		t.Errorf("token user = %s", tok.User)
	}
	if tok.Resource != "prod-vault" {
		t.Errorf("token resource = %s", tok.Resource)
	}
	if tok.JustificationType != "break_glass" {
		t.Errorf("justification type = %s, want 'break_glass'", tok.JustificationType)
	}
}

// TestActivateRejectsMissingFields ensures empty user/resource fails fast.
func TestActivateRejectsMissingFields(t *testing.T) {
	mgr := NewManager(map[string]string{"x": "00"}, &providers.DemoIssuer{}, nil)

	_, reason, err := mgr.Activate(context.Background(), BreakGlassRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reason == "" {
		t.Error("expected rejection reason for missing fields")
	}
}

// TestTTLCeiling ensures TTL is clamped to models.MaxTTL.
func TestTTLCeiling(t *testing.T) {
	pub1, priv1, _ := GenerateKeyPair()
	pub2, priv2, _ := GenerateKeyPair()

	mgr := NewManager(map[string]string{"a": pub1, "b": pub2}, &providers.DemoIssuer{}, nil)

	req := BreakGlassRequest{
		User:       "x@x.com",
		Resource:   "r",
		Reason:     "test",
		TTLMinutes: 9999, // way over the 60-minute ceiling
	}
	sig1, _ := SignMessage(priv1, req)
	sig2, _ := SignMessage(priv2, req)
	req.Signatures = []ApprovalSignature{
		{ApproverID: "a", Signature: sig1},
		{ApproverID: "b", Signature: sig2},
	}

	tok, _, err := mgr.Activate(context.Background(), req)
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if tok == nil {
		t.Fatal("expected token")
	}
	// TTL should be clamped to 60 minutes
	if time.Until(tok.ExpiresAt) > 61*time.Minute {
		t.Errorf("TTL not clamped: expires_at = %s", tok.ExpiresAt)
	}
}