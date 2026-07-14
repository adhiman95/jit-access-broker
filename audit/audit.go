// Package audit provides structured, immutable JSON event logging to stdout.
//
// Every significant lifecycle event (token requested, granted, denied, revoked,
// extended, break-glass used) is emitted as a single-line JSON object with a
// stable schema. This format is designed for ingestion by log collectors like
// Fluentd, Filebeat, or Loki.
//
// All events include:
//   - timestamp (RFC3339Nano UTC)
//   - event_type
//   - session_id (correlates all events for one access session)
//   - actor (the user identity)
//   - resource
//   - outcome (success | failure)
//   - metadata (event-specific fields)
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/example/jit-access-broker/models"
)

// EventType enumerates the auditable event types.
type EventType string

const (
	EventRequested    EventType = "access.requested"
	EventGranted      EventType = "access.granted"
	EventDenied       EventType = "access.denied"
	EventRevoked      EventType = "access.revoked"
	EventExtended     EventType = "access.extended"
	EventWarningSent  EventType = "access.warning_sent"
	EventBreakGlass   EventType = "access.break_glass"
	EventRevokeFailed EventType = "access.revoke_failed"
)

// Outcome describes whether the event succeeded or failed.
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
)

// Event is the canonical audit record.
type Event struct {
	Timestamp string         `json:"timestamp"`
	EventType EventType      `json:"event_type"`
	SessionID string         `json:"session_id"`
	Actor     string         `json:"actor"`
	Resource  string         `json:"resource"`
	Provider  string         `json:"provider,omitempty"`
	Outcome   Outcome        `json:"outcome"`
	Reason    string         `json:"reason,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// Logger writes Events as single-line JSON to an io.Writer (default: stdout).
type Logger struct {
	mu    sync.Mutex
	Out   io.Writer
	clock func() time.Time
}

// NewLogger creates a Logger writing to stdout.
func NewLogger() *Logger {
	return &Logger{
		Out:   os.Stdout,
		clock: time.Now,
	}
}

// NewLoggerWith creates a Logger with a custom writer (used in tests).
func NewLoggerWith(w io.Writer) *Logger {
	return &Logger{
		Out:   w,
		clock: time.Now,
	}
}

// Emit writes a single event as one JSON line.
func (l *Logger) Emit(e Event) {
	if l.Out == nil {
		l.Out = os.Stdout
	}
	if e.Timestamp == "" {
		e.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	line, err := json.Marshal(e)
	if err != nil {
		// Last-resort fallback — should never happen for this struct
		fmt.Fprintf(l.Out, `{"event_type":"audit_error","reason":%q}`+"\n", err.Error())
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintln(l.Out, string(line))
}

// LogRequested logs an access request attempt.
func (l *Logger) LogRequested(sessionID, user, resource, jType, jRef string) {
	l.Emit(Event{
		EventType: EventRequested,
		SessionID: sessionID,
		Actor:     user,
		Resource:  resource,
		Outcome:   OutcomeSuccess,
		Metadata: map[string]any{
			"justification_type": jType,
			"justification_ref":  jRef,
		},
	})
}

// LogGranted logs a successful token grant.
func (l *Logger) LogGranted(tok *models.IssuedToken, ttlSeconds int) {
	l.Emit(Event{
		EventType: EventGranted,
		SessionID: tok.ID,
		Actor:     tok.User,
		Resource:  tok.Resource,
		Provider:  tok.Provider,
		Outcome:   OutcomeSuccess,
		Metadata: map[string]any{
			"ttl_seconds":     ttlSeconds,
			"expires_at":      tok.ExpiresAt.UTC().Format(time.RFC3339),
			"issued_at":       tok.IssuedAt.UTC().Format(time.RFC3339),
			"max_session_at":  tok.OriginalIssuedAt.Add(models.MaxSessionDuration).UTC().Format(time.RFC3339),
		},
	})
}

// LogDenied logs a denied access request.
func (l *Logger) LogDenied(sessionID, user, resource, reason string) {
	l.Emit(Event{
		EventType: EventDenied,
		SessionID: sessionID,
		Actor:     user,
		Resource:  resource,
		Outcome:   OutcomeFailure,
		Reason:    reason,
	})
}

// LogRevoked logs a token revocation (auto or manual).
func (l *Logger) LogRevoked(tok *models.IssuedToken, source string) {
	l.Emit(Event{
		EventType: EventRevoked,
		SessionID: tok.ID,
		Actor:     tok.User,
		Resource:  tok.Resource,
		Provider:  tok.Provider,
		Outcome:   OutcomeSuccess,
		Metadata: map[string]any{
			"source":     source, // "auto" | "manual" | "ceiling"
			"expires_at": tok.ExpiresAt.UTC().Format(time.RFC3339),
		},
	})
}

// LogExtended logs a successful session extension.
func (l *Logger) LogExtended(tok *models.IssuedToken, newExpiry time.Time, extensionsLeft int) {
	l.Emit(Event{
		EventType: EventExtended,
		SessionID: tok.ID,
		Actor:     tok.User,
		Resource:  tok.Resource,
		Provider:  tok.Provider,
		Outcome:   OutcomeSuccess,
		Metadata: map[string]any{
			"new_expires_at":   newExpiry.UTC().Format(time.RFC3339),
			"extension_count":  tok.ExtensionCount,
			"extensions_left":  extensionsLeft,
		},
	})
}

// LogWarningSent logs an impending-expiry notification.
func (l *Logger) LogWarningSent(tok *models.IssuedToken, timeLeft time.Duration) {
	l.Emit(Event{
		EventType: EventWarningSent,
		SessionID: tok.ID,
		Actor:     tok.User,
		Resource:  tok.Resource,
		Outcome:   OutcomeSuccess,
		Metadata: map[string]any{
			"time_left_seconds": int(timeLeft.Seconds()),
		},
	})
}

// LogBreakGlass logs a quorum break-glass activation.
func (l *Logger) LogBreakGlass(sessionID, user, resource string, approvers []string) {
	l.Emit(Event{
		EventType: EventBreakGlass,
		SessionID: sessionID,
		Actor:     user,
		Resource:  resource,
		Outcome:   OutcomeSuccess,
		Metadata: map[string]any{
			"approvers":       approvers,
			"quorum_required": 2,
			"quorum_met":      len(approvers),
		},
	})
}

// LogRevokeFailed logs a failed revocation attempt (used by retry engine).
func (l *Logger) LogRevokeFailed(tok *models.IssuedToken, attempt int, err error) {
	l.Emit(Event{
		EventType: EventRevokeFailed,
		SessionID: tok.ID,
		Actor:     tok.User,
		Resource:  tok.Resource,
		Outcome:   OutcomeFailure,
		Reason:    err.Error(),
		Metadata: map[string]any{
			"attempt": attempt,
		},
	})
}

// NoopLogger discards all events — used in tests that don't assert on audit.
type NoopLogger struct{}

func (NoopLogger) Emit(Event)                                  {}
func (n NoopLogger) LogRequested(string, string, string, string, string) {}
func (n NoopLogger) LogGranted(*models.IssuedToken, int)       {}
func (n NoopLogger) LogDenied(string, string, string, string)  {}
func (n NoopLogger) LogRevoked(*models.IssuedToken, string)    {}
func (n NoopLogger) LogExtended(*models.IssuedToken, time.Time, int) {}
func (n NoopLogger) LogWarningSent(*models.IssuedToken, time.Duration) {}
func (n NoopLogger) LogBreakGlass(string, string, string, []string)   {}
func (n NoopLogger) LogRevokeFailed(*models.IssuedToken, int, error)  {}