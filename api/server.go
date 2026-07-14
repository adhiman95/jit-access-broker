// Package api exposes the stateless HTTP API of the JIT Access Broker.
//
//	POST /api/v1/access/request       — request + maybe-provision ephemeral access
//	POST /api/v1/access/extend        — extend an existing session (context-aware)
//	GET  /api/v1/access/tokens        — list live tokens
//	POST /api/v1/access/revoke/:id    — manually revoke a token
//	POST /api/v1/breakglass/activate  — emergency quorum-based access
//	GET  /healthz                     — liveness probe
package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/example/jit-access-broker/audit"
	"github.com/example/jit-access-broker/auth"
	"github.com/example/jit-access-broker/breakglass"
	"github.com/example/jit-access-broker/models"
	"github.com/example/jit-access-broker/providers"
	"github.com/example/jit-access-broker/slack"
	"github.com/example/jit-access-broker/store"
)

// Server bundles the dependencies injected into the HTTP handlers.
type Server struct {
	Engine    *auth.Engine
	Issuer    providers.TokenIssuer
	Store     *store.Store
	TTL       time.Duration
	auditLog  *audit.Logger
	bgManager *breakglass.Manager
	slackHandler *slack.Handler
}

// NewServer constructs the Server dependency bundle.
func NewServer(engine *auth.Engine, issuer providers.TokenIssuer, st *store.Store, ttl time.Duration) *Server {
	return &Server{Engine: engine, Issuer: issuer, Store: st, TTL: ttl}
}

// SetAuditLogger wires the structured audit logger.
func (s *Server) SetAuditLogger(l *audit.Logger) {
	s.auditLog = l
}

// SetBreakGlassManager wires the emergency break-glass manager.
func (s *Server) SetBreakGlassManager(m *breakglass.Manager) {
	s.bgManager = m
}

// SetSlackHandler wires the optional Slack ChatOps handler.
func (s *Server) SetSlackHandler(h *slack.Handler) {
	s.slackHandler = h
}

// Router returns the http.Handler used by the HTTP server.
func (s *Server) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.healthz)
	mux.HandleFunc("/api/v1/access/request", s.requestAccess)
	mux.HandleFunc("/api/v1/access/extend", s.extendAccess)
	mux.HandleFunc("/api/v1/access/tokens", s.listTokens)
	mux.HandleFunc("/api/v1/access/revoke/", s.revokeToken) // trailing slash for :id
	mux.HandleFunc("/api/v1/breakglass/activate", s.breakGlassActivate)
	if s.slackHandler != nil {
		mux.HandleFunc("/slack/command", s.slackHandler.Handle)
	}
	return logging(mux)
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// requestAccess is the core endpoint: validate context → issue token.
func (s *Server) requestAccess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, models.ErrorResponse{
			Error: "method_not_allowed", Status: http.StatusMethodNotAllowed,
		})
		return
	}
	var req models.AccessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, models.ErrorResponse{
			Error: "invalid_json", Reason: err.Error(), Status: http.StatusBadRequest,
		})
		return
	}

	// 1. Contextual validation
	res, err := s.Engine.Validate(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, models.ErrorResponse{
			Error: "validation_transport_error", Reason: res.Reason, Status: http.StatusBadGateway,
		})
		return
	}
	if !res.OK {
		if s.auditLog != nil {
			s.auditLog.LogDenied("", req.UserIdentity, req.Resource, res.Reason)
		}
		writeJSON(w, http.StatusForbidden, models.ErrorResponse{
			Error: "context_validation_failed", Reason: res.Reason, Status: http.StatusForbidden,
		})
		return
	}

	// 2. Dynamic token provisioning
	tok, err := s.Issuer.Issue(r.Context(), req.UserIdentity, req.Resource, s.TTL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, models.ErrorResponse{
			Error: "token_issue_failed", Reason: err.Error(), Status: http.StatusInternalServerError,
		})
		return
	}

	// Store justification so Extend can re-validate later
	tok.JustificationType = req.JustificationType
	tok.JustificationRef = req.JustificationRef

	// 3. Register for self-destruction
	s.Store.Add(tok)

	// 4. Audit log
	if s.auditLog != nil {
		s.auditLog.LogGranted(tok, int(s.TTL.Seconds()))
	}

	// 5. Respond
	maxSessionAt := tok.OriginalIssuedAt.Add(models.MaxSessionDuration)
	writeJSON(w, http.StatusOK, models.AccessResponse{
		Granted:      true,
		Token:        tok.Token,
		TokenID:      tok.ID,
		Resource:     tok.Resource,
		IssuedAt:     tok.IssuedAt,
		ExpiresAt:    tok.ExpiresAt,
		TTLSeconds:   int(s.TTL.Seconds()),
		MaxSessionAt: maxSessionAt,
	})
}

// extendAccess handles POST /api/v1/access/extend.
func (s *Server) extendAccess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, models.ErrorResponse{Error: "method_not_allowed"})
		return
	}
	var req models.ExtensionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, models.ErrorResponse{
			Error: "invalid_json", Reason: err.Error(), Status: http.StatusBadRequest,
		})
		return
	}
	if req.TokenID == "" {
		writeJSON(w, http.StatusBadRequest, models.ErrorResponse{Error: "missing_token_id"})
		return
	}

	tok := s.Store.Get(req.TokenID)
	if tok == nil {
		writeJSON(w, http.StatusNotFound, models.ErrorResponse{
			Error: "token_not_found", Status: http.StatusNotFound,
		})
		return
	}

	// Re-validate the operational context
	accessReq := models.AccessRequest{
		UserIdentity:      req.UserIdentity,
		Resource:          tok.Resource,
		JustificationType: req.JustificationType,
		JustificationRef:  req.JustificationRef,
	}
	res, err := s.Engine.Validate(r.Context(), accessReq)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, models.ErrorResponse{
			Error: "validation_transport_error", Reason: res.Reason, Status: http.StatusBadGateway,
		})
		return
	}
	if !res.OK {
		// Context no longer valid → revoke immediately
		_ = s.Store.RevokeNow(r.Context(), req.TokenID)
		writeJSON(w, http.StatusForbidden, models.ExtensionResponse{
			Extended: false,
			TokenID:  req.TokenID,
			Reason:   "context no longer valid — token revoked: " + res.Reason,
		})
		return
	}

	// Context valid → attempt extension (enforces session ceiling)
	result := s.Store.Extend(r.Context(), req.TokenID)
	if !result.Extended {
		status := http.StatusForbidden
		if strings.Contains(result.Reason, "not found") {
			status = http.StatusNotFound
		}
		writeJSON(w, status, models.ExtensionResponse{
			Extended: false,
			TokenID:  req.TokenID,
			Reason:   result.Reason,
		})
		return
	}

	if s.auditLog != nil {
		s.auditLog.LogExtended(result.Token, result.NewExpiresAt, result.ExtensionsLeft)
	}

	writeJSON(w, http.StatusOK, models.ExtensionResponse{
		Extended:       true,
		TokenID:        req.TokenID,
		NewExpiresAt:   result.NewExpiresAt,
		ExtensionsLeft: result.ExtensionsLeft,
		MaxSessionAt:   result.MaxSessionAt,
	})
}

// listTokens returns the live token set (without exposing secret material).
func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, models.ErrorResponse{Error: "method_not_allowed"})
		return
	}
	type safe struct {
		ID               string    `json:"id"`
		User             string    `json:"user"`
		Resource         string    `json:"resource"`
		Provider         string    `json:"provider"`
		IssuedAt         time.Time `json:"issued_at"`
		ExpiresAt        time.Time `json:"expires_at"`
		OriginalIssuedAt time.Time `json:"original_issued_at"`
		ExtensionCount   int       `json:"extension_count"`
	}
	live := s.Store.List()
	out := make([]safe, 0, len(live))
	for _, t := range live {
		out = append(out, safe{
			ID: t.ID, User: t.User, Resource: t.Resource, Provider: t.Provider,
			IssuedAt: t.IssuedAt, ExpiresAt: t.ExpiresAt,
			OriginalIssuedAt: t.OriginalIssuedAt, ExtensionCount: t.ExtensionCount,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": out, "count": len(out)})
}

// revokeToken manually revokes a token by id parsed from the path.
func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, models.ErrorResponse{Error: "method_not_allowed"})
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/access/revoke/")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, models.ErrorResponse{Error: "missing_token_id"})
		return
	}
	if s.Store.Get(id) == nil {
		writeJSON(w, http.StatusNotFound, models.ErrorResponse{Error: "token_not_found", Status: http.StatusNotFound})
		return
	}
	if err := s.Store.RevokeNow(r.Context(), id); err != nil {
		writeJSON(w, http.StatusInternalServerError, models.ErrorResponse{
			Error: "revoke_failed", Reason: err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"revoked": id})
}

// breakGlassActivate handles POST /api/v1/breakglass/activate.
//
// This is the emergency access pathway for when external validation
// providers are unreachable. Requires a 2-of-3 quorum of Ed25519
// approver signatures.
func (s *Server) breakGlassActivate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, models.ErrorResponse{Error: "method_not_allowed"})
		return
	}
	if s.bgManager == nil {
		writeJSON(w, http.StatusServiceUnavailable, models.ErrorResponse{
			Error: "break_glass_disabled", Reason: "no trusted approvers configured",
		})
		return
	}
	var req breakglass.BreakGlassRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, models.ErrorResponse{
			Error: "invalid_json", Reason: err.Error(),
		})
		return
	}

	tok, reason, err := s.bgManager.Activate(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, models.ErrorResponse{
			Error: "break_glass_failed", Reason: err.Error(),
		})
		return
	}
	if tok == nil {
		writeJSON(w, http.StatusForbidden, models.ErrorResponse{
			Error: "break_glass_rejected", Reason: reason,
		})
		return
	}

	// Register for self-destruction
	s.Store.Add(tok)

	writeJSON(w, http.StatusOK, models.AccessResponse{
		Granted:      true,
		Token:        tok.Token,
		TokenID:      tok.ID,
		Resource:     tok.Resource,
		IssuedAt:     tok.IssuedAt,
		ExpiresAt:    tok.ExpiresAt,
		TTLSeconds:   int(time.Until(tok.ExpiresAt).Seconds()),
		MaxSessionAt: tok.OriginalIssuedAt.Add(models.MaxSessionDuration),
	})
}

// writeJSON is the canonical JSON response helper.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// logging is a minimal access-log middleware (also useful in test assertions).
func logging(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h.ServeHTTP(w, r)
		_ = start
	})
}