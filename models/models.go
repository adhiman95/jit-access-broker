// Package models defines shared request/response types and core domain
// objects for the JIT Ephemeral Access Broker.
package models

import "time"

// AccessRequest is the JSON payload accepted by
// POST /api/v1/access/request.
type AccessRequest struct {
	// UserIdentity is the requesting principal (email or unique id).
	UserIdentity string `json:"user_identity"`

	// Resource is the target resource identifier (e.g. AWS role ARN,
	// Vault path, k8s namespace).
	Resource string `json:"resource"`

	// JustificationType is the kind of operational context being supplied.
	// Allowed values: "pagerduty" | "jira".
	JustificationType string `json:"justification_type"`

	// JustificationRef is the incident id / issue key referenced as the
	// reason for access.
	JustificationRef string `json:"justification_ref"`
}

// AccessResponse is returned on a successful access grant.
type AccessResponse struct {
	Granted      bool      `json:"granted"`
	Token        string    `json:"token,omitempty"`
	TokenID      string    `json:"token_id,omitempty"`
	Resource     string    `json:"resource,omitempty"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	TTLSeconds   int       `json:"ttl_seconds"`
	MaxSessionAt time.Time `json:"max_session_at,omitempty"` // absolute ceiling
}

// ErrorResponse is returned for all non-grant outcomes.
type ErrorResponse struct {
	Error  string `json:"error"`
	Reason string `json:"reason,omitempty"`
	Status int    `json:"status,omitempty"`
}

// IssuedToken is the internal representation of a token that has been
// provisioned and is tracked by the revocation worker.
type IssuedToken struct {
	ID              string    `json:"id"`
	User            string    `json:"user"`
	Resource        string    `json:"resource"`
	Token           string    `json:"token"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	Provider        string    `json:"provider"`
	Revoked         bool      `json:"revoked"`
	OriginalIssuedAt time.Time `json:"original_issued_at"` // never changes across extensions
	ExtensionCount  int       `json:"extension_count"`     // how many times extended
	NotifiedExpiry  bool      `json:"-"`                    // internal: warning already sent
	// JustificationType/Ref stored so the engine can re-validate on extension.
	JustificationType string `json:"justification_type"`
	JustificationRef  string `json:"justification_ref"`
}

// SessionAge returns how long this session has been continuously alive
// (from original issuance to now), regardless of extensions.
func (t *IssuedToken) SessionAge(now time.Time) time.Duration {
	return now.Sub(t.OriginalIssuedAt)
}

// ExtensionRequest is the JSON payload for POST /api/v1/access/extend.
type ExtensionRequest struct {
	TokenID          string `json:"token_id"`
	UserIdentity     string `json:"user_identity"`
	JustificationType string `json:"justification_type"`
	JustificationRef  string `json:"justification_ref"`
}

// ExtensionResponse is returned on an extension attempt.
type ExtensionResponse struct {
	Extended      bool      `json:"extended"`
	TokenID       string    `json:"token_id"`
	NewExpiresAt  time.Time `json:"new_expires_at,omitempty"`
	ExtensionsLeft int      `json:"extensions_left,omitempty"`
	MaxSessionAt  time.Time `json:"max_session_at,omitempty"`
	Reason        string    `json:"reason,omitempty"`
}

// MaxTTL is the hard ceiling per individual token grant (60 minutes)
// mandated by the spec. Any configured or requested TTL above this
// value is rejected.
const MaxTTL = 60 * time.Minute

// MaxSessionDuration is the absolute ceiling for the total continuous
// session age across ALL extensions (e.g. 4 hours). No matter how many
// extensions are granted, once session age hits this limit the token
// is forcibly revoked and cannot be extended further.
const MaxSessionDuration = 4 * time.Hour

// WarningBeforeExpiry is how long before expiry the broker fires the
// "impending expiration" notification (default 15 minutes for a 60-min TTL,
// i.e. at the 45-minute mark).
const WarningBeforeExpiry = 15 * time.Minute