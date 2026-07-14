// Package breakglass implements an emergency break-glass access pathway for
// when external validation providers (PagerDuty/Jira) are completely
// unreachable.
//
// Break-glass activation requires a 2-of-3 quorum: at least two of three
// pre-registered engineer authorization keys must cryptographically sign the
// access request. The signatures are verified against Ed25519 public keys
// stored in the config.
//
// This ensures that even in a total API outage, access can be granted with
// human accountability, but no single person can self-approve emergency
// production access.
package breakglass

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/example/jit-access-broker/audit"
	"github.com/example/jit-access-broker/models"
	"github.com/example/jit-access-broker/providers"
)

// QuorumRequired is the minimum number of valid distinct approvals needed.
const QuorumRequired = 2

// BreakGlassRequest is the JSON payload for emergency access.
type BreakGlassRequest struct {
	User         string            `json:"user"`
	Resource     string            `json:"resource"`
	Reason       string            `json:"reason"`
	TTLMinutes   int               `json:"ttl_minutes"`
	Signatures   []ApprovalSignature `json:"signatures"`
}

// ApprovalSignature binds an approver identity to their Ed25519 signature.
type ApprovalSignature struct {
	ApproverID string `json:"approver_id"` // matches a key in config
	Signature  string `json:"signature"`   // hex-encoded Ed25519 signature
}

// Manager verifies break-glass requests and issues emergency tokens.
type Manager struct {
	// TrustedApprovers maps approver_id → Ed25519 public key (hex-encoded)
	TrustedApprovers map[string]string
	Issuer           providers.TokenIssuer
	Logger           *audit.Logger
}

// NewManager creates a break-glass manager.
func NewManager(approvers map[string]string, issuer providers.TokenIssuer, logger *audit.Logger) *Manager {
	return &Manager{
		TrustedApprovers: approvers,
		Issuer:           issuer,
		Logger:           logger,
	}
}

// Verify checks that the request carries a valid 2-of-3 quorum of distinct
// approver signatures over the canonical request message.
//
// The canonical message is: user|resource|reason|ttl_minutes
func (m *Manager) Verify(req BreakGlassRequest) (bool, string, []string, error) {
	if req.User == "" || req.Resource == "" {
		return false, "user and resource are required", nil, nil
	}
	if len(req.Signatures) < QuorumRequired {
		return false, fmt.Sprintf("insufficient signatures: got %d, need %d", len(req.Signatures), QuorumRequired), nil, nil
	}

	message := CanonicalMessage(req)
	verifiedApprovers := make(map[string]bool)
	var approverList []string

	for _, sig := range req.Signatures {
		// Check this approver is trusted
		pubKeyHex, ok := m.TrustedApprovers[sig.ApproverID]
		if !ok {
			continue // unknown approver — skip
		}

		// Decode the public key
		pubKeyBytes, err := hex.DecodeString(pubKeyHex)
		if err != nil {
			continue
		}
		if len(pubKeyBytes) != ed25519.PublicKeySize {
			continue
		}

		// Decode the signature
		sigBytes, err := hex.DecodeString(sig.Signature)
		if err != nil {
			continue
		}
		if len(sigBytes) != ed25519.SignatureSize {
			continue
		}

		// Verify the signature
		if !ed25519.Verify(pubKeyBytes, []byte(message), sigBytes) {
			continue // invalid signature — skip
		}

		// Deduplicate: only add to approverList if not already verified
		if !verifiedApprovers[sig.ApproverID] {
			verifiedApprovers[sig.ApproverID] = true
			approverList = append(approverList, sig.ApproverID)
		}
	}

	if len(verifiedApprovers) < QuorumRequired {
		return false, fmt.Sprintf("quorum not met: %d valid signature(s), need %d", len(verifiedApprovers), QuorumRequired), approverList, nil
	}

	return true, "", approverList, nil
}

// Activate verifies the quorum and issues an emergency token.
func (m *Manager) Activate(ctx context.Context, req BreakGlassRequest) (*models.IssuedToken, string, error) {
	ok, reason, approvers, err := m.Verify(req)
	if err != nil {
		return nil, "", fmt.Errorf("break-glass verify: %w", err)
	}
	if !ok {
		return nil, reason, nil
	}

	// Enforce TTL ceiling
	ttl := time.Duration(req.TTLMinutes) * time.Minute
	if ttl <= 0 || ttl > models.MaxTTL {
		ttl = models.MaxTTL
	}

	tok, err := m.Issuer.Issue(ctx, req.User, req.Resource, ttl)
	if err != nil {
		return nil, "", fmt.Errorf("break-glass issue: %w", err)
	}

	// Tag the token metadata
	tok.JustificationType = "break_glass"
	tok.JustificationRef = req.Reason

	// Audit log
	if m.Logger != nil {
		m.Logger.LogBreakGlass(tok.ID, req.User, req.Resource, approvers)
	}

	return tok, "", nil
}

// CanonicalMessage builds the deterministic message that approvers must sign.
func CanonicalMessage(req BreakGlassRequest) string {
	return fmt.Sprintf("%s|%s|%s|%d", req.User, req.Resource, req.Reason, req.TTLMinutes)
}

// SignMessage signs the canonical message with an Ed25519 private key.
// This is a helper for CLI usage / testing — approvers would use this to
// create their signature.
func SignMessage(privKeyHex string, req BreakGlassRequest) (string, error) {
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return "", fmt.Errorf("invalid private key hex: %w", err)
	}
	if len(privKeyBytes) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(privKeyBytes))
	}
	msg := CanonicalMessage(req)
	sig := ed25519.Sign(privKeyBytes, []byte(msg))
	return hex.EncodeToString(sig), nil
}

// GenerateKeyPair creates a new Ed25519 key pair for an approver.
// Returns (publicKeyHex, privateKeyHex, error).
func GenerateKeyPair() (string, string, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(pub), hex.EncodeToString(priv), nil
}

// MarshalForJSON is a helper to serialize a BreakGlassRequest for debugging.
func MarshalForJSON(req BreakGlassRequest) string {
	b, _ := json.Marshal(req)
	return string(b)
}