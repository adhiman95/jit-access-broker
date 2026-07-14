package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/example/jit-access-broker/models"
	"github.com/example/jit-access-broker/providers"
)

type stubValidator struct {
	ok     bool
	reason string
	err    error
}

func (s stubValidator) Validate(ctx context.Context, user, ref string) (bool, string, error) {
	return s.ok, s.reason, s.err
}

func toProviders(m map[string]stubValidator) map[string]providers.ContextValidator {
	out := make(map[string]providers.ContextValidator, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func TestEngineValidateSuccess(t *testing.T) {
	e := NewEngine(toProviders(map[string]stubValidator{"pagerduty": {ok: true}}))
	res, err := e.Validate(context.Background(), models.AccessRequest{
		UserIdentity: "alice", Resource: "db", JustificationType: "pagerduty", JustificationRef: "INC1",
	})
	if err != nil || !res.OK {
		t.Fatalf("expected ok, got %+v err=%v", res, err)
	}
}

func TestEngineValidateFailureReason(t *testing.T) {
	e := NewEngine(toProviders(map[string]stubValidator{"jira": {ok: false, reason: "wrong assignee"}}))
	res, _ := e.Validate(context.Background(), models.AccessRequest{
		UserIdentity: "alice", Resource: "db", JustificationType: "jira", JustificationRef: "J-1",
	})
	if res.OK {
		t.Fatal("expected failure")
	}
	if res.Reason != "wrong assignee" {
		t.Errorf("reason = %q", res.Reason)
	}
}

func TestEngineValidateTransportError(t *testing.T) {
	e := NewEngine(toProviders(map[string]stubValidator{"pagerduty": {err: errors.New("network down")}}))
	_, err := e.Validate(context.Background(), models.AccessRequest{
		UserIdentity: "alice", Resource: "db", JustificationType: "pagerduty", JustificationRef: "INC1",
	})
	if err == nil {
		t.Fatal("expected transport error")
	}
}

func TestEngineValidateUnsupportedType(t *testing.T) {
	e := NewEngine(toProviders(map[string]stubValidator{}))
	res, _ := e.Validate(context.Background(), models.AccessRequest{
		UserIdentity: "a", Resource: "r", JustificationType: "slack", JustificationRef: "x",
	})
	if res.OK {
		t.Fatal("expected failure for unsupported type")
	}
}

func TestEngineValidateMissingFields(t *testing.T) {
	e := NewEngine(toProviders(map[string]stubValidator{"pagerduty": {ok: true}}))
	cases := []models.AccessRequest{
		{},
		{UserIdentity: "a"},
		{UserIdentity: "a", Resource: "r"},
		{UserIdentity: "a", Resource: "r", JustificationType: "pagerduty"},
	}
	for i, c := range cases {
		res, _ := e.Validate(context.Background(), c)
		if res.OK {
			t.Errorf("case %d: expected failure for %+v", i, c)
		}
	}
}