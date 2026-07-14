// Package persistence provides durable session lifecycle storage so the
// broker survives restarts without orphaning tokens.
//
// On startup, LoadAll() reads the persistence file and returns all token
// records. The store layer scans these for missed expirations and executes
// immediate cleanups.
//
// On every token state change (issue, extend, revoke), the store calls
// Save() or Delete() to keep the file in sync.
//
// Implementation note: we use a JSON file store instead of CGO-bound SQLite
// to guarantee the binary compiles with `CGO_ENABLED=0` (pure Go). The
// interface is designed so a real SQLite backend can be dropped in later
// without changing the callers.
package persistence

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/example/jit-access-broker/models"
)

// Record is the on-disk representation of a token's lifecycle state.
// It mirrors models.IssuedToken but is versioned for future schema changes.
type Record struct {
	Version          int       `json:"version"`
	ID               string    `json:"id"`
	User             string    `json:"user"`
	Resource         string    `json:"resource"`
	Token            string    `json:"token"`
	Provider         string    `json:"provider"`
	IssuedAt         time.Time `json:"issued_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	OriginalIssuedAt time.Time `json:"original_issued_at"`
	ExtensionCount   int       `json:"extension_count"`
	Revoked          bool      `json:"revoked"`
	RevocationPending bool     `json:"revocation_pending"` // revocation attempted but failed (retry)
	JustificationType string  `json:"justification_type"`
	JustificationRef  string  `json:"justification_ref"`
}

// Store is the file-backed persistence layer.
type Store struct {
	mu   sync.Mutex
	path string
}

// New creates (or opens) a persistence store at the given file path.
func New(path string) *Store {
	return &Store{path: path}
}

// SaveAll atomically writes all records to disk.
func (s *Store) SaveAll(records []Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("persistence: marshal: %w", err)
	}

	// Atomic write: write to temp file, then rename
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("persistence: write tmp: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("persistence: rename: %w", err)
	}
	return nil
}

// LoadAll reads all records from disk. Returns an empty slice if the file
// doesn't exist yet (first run).
func (s *Store) LoadAll() ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return []Record{}, nil // first run — no error
		}
		return nil, fmt.Errorf("persistence: read: %w", err)
	}

	var records []Record
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("persistence: unmarshal: %w", err)
	}
	return records, nil
}

// LoadActive returns only non-revoked records (tokens that may still need
// cleanup on startup).
func (s *Store) LoadActive() ([]Record, error) {
	all, err := s.LoadAll()
	if err != nil {
		return nil, err
	}
	var active []Record
	for _, r := range all {
		if !r.Revoked {
			active = append(active, r)
		}
	}
	return active, nil
}

// ToRecord converts an IssuedToken to a persistence Record.
func ToRecord(t *models.IssuedToken) Record {
	return Record{
		Version:           1,
		ID:                t.ID,
		User:              t.User,
		Resource:          t.Resource,
		Token:             t.Token,
		Provider:          t.Provider,
		IssuedAt:          t.IssuedAt,
		ExpiresAt:         t.ExpiresAt,
		OriginalIssuedAt:  t.OriginalIssuedAt,
		ExtensionCount:    t.ExtensionCount,
		Revoked:           t.Revoked,
		JustificationType: t.JustificationType,
		JustificationRef:  t.JustificationRef,
	}
}

// ToToken converts a persistence Record back to an IssuedToken.
func (r Record) ToToken() *models.IssuedToken {
	return &models.IssuedToken{
		ID:                r.ID,
		User:              r.User,
		Resource:          r.Resource,
		Token:             r.Token,
		Provider:          r.Provider,
		IssuedAt:          r.IssuedAt,
		ExpiresAt:         r.ExpiresAt,
		OriginalIssuedAt:  r.OriginalIssuedAt,
		ExtensionCount:    r.ExtensionCount,
		Revoked:           r.Revoked,
		JustificationType: r.JustificationType,
		JustificationRef:  r.JustificationRef,
	}
}

// MissedExpirations scans loaded records and returns those whose ExpiresAt
// has already passed (i.e. the broker was down when the TTL elapsed).
func MissedExpirations(records []Record, now time.Time) []Record {
	var missed []Record
	for _, r := range records {
		if !r.Revoked && r.ExpiresAt.Before(now) {
			missed = append(missed, r)
		}
	}
	return missed
}