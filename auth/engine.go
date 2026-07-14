// Package auth contains the Contextual Validation Engine. It is the brain
// that decides whether a JIT access request should be allowed to proceed to
// token issuance. It delegates the actual external lookups to pluggable
// ContextValidator implementations (PagerDuty / Jira).
package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/example/jit-access-broker/models"
	"github.com/example/jit-access-broker/providers"
)

// Engine is the Contextual Validation Engine.
type Engine struct {
	validators map[string]providers.ContextValidator
}

// NewEngine constructs an Engine from a map of justification-type → validator.
// e.g. {"pagerduty": pdClient, "jira": jiraClient}.
func NewEngine(validators map[string]providers.ContextValidator) *Engine {
	if validators == nil {
		validators = map[string]providers.ContextValidator{}
	}
	return &Engine{validators: validators}
}

// ValidationResult bundles the outcome for downstream consumers.
type ValidationResult struct {
	OK     bool
	Reason string
	Provider string
	Ref    string
}

// Validate selects the correct validator based on JustificationType and runs
// it. It returns a descriptive ValidationResult and any transport error.
func (e *Engine) Validate(ctx context.Context, req models.AccessRequest) (ValidationResult, error) {
	if strings.TrimSpace(req.UserIdentity) == "" {
		return ValidationResult{OK: false, Reason: "user_identity is required"}, nil
	}
	if strings.TrimSpace(req.Resource) == "" {
		return ValidationResult{OK: false, Reason: "resource is required"}, nil
	}
	jt := strings.ToLower(strings.TrimSpace(req.JustificationType))
	if jt == "" {
		return ValidationResult{OK: false, Reason: "justification_type is required (pagerduty|jira)"}, nil
	}
	if strings.TrimSpace(req.JustificationRef) == "" {
		return ValidationResult{OK: false, Reason: "justification_ref is required"}, nil
	}

	v, ok := e.validators[jt]
	if !ok {
		return ValidationResult{OK: false, Reason: fmt.Sprintf("unsupported justification_type %q", jt)}, nil
	}

	ok, reason, err := v.Validate(ctx, req.UserIdentity, req.JustificationRef)
	if err != nil {
		return ValidationResult{OK: false, Reason: "context validation error: " + err.Error(), Provider: jt, Ref: req.JustificationRef}, err
	}
	return ValidationResult{OK: ok, Reason: reason, Provider: jt, Ref: req.JustificationRef}, nil
}