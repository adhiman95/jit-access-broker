package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/example/jit-access-broker/models"
)

func writeTempYAML(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	return p
}

func TestLoadValid(t *testing.T) {
	yaml := `
server:
  addr: ":9090"
  shutdown_timeout: 3s
token_ttl: 60m
providers:
  pagerduty:
    api_base_url: "https://api.pagerduty.com"
    api_token: "tok"
  jira:
    api_base_url: "https://x.atlassian.net"
    username: "bot@x.com"
    api_token: "jt"
vault:
  addr: "https://127.0.0.1:8200"
  token: "root"
  token_ttl: 60m
  max_tokens_per_user: 5
`
	p := writeTempYAML(t, "valid.yaml", yaml)
	c, err := Load(p)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if c.Server.Addr != ":9090" {
		t.Errorf("addr = %q, want :9090", c.Server.Addr)
	}
	if c.TokenTTL != 60*time.Minute {
		t.Errorf("ttl = %v, want 60m", c.TokenTTL)
	}
	if c.Vault.MaxTokensPerUser != 5 {
		t.Errorf("max tokens = %d, want 5", c.Vault.MaxTokensPerUser)
	}
}

func TestLoadRejectsExcessiveTTL(t *testing.T) {
	yaml := `
server: {addr: ":80"}
token_ttl: 120m
providers:
  pagerduty: {api_token: x}
  jira: {api_token: x}
vault: {addr: "https://v", token_ttl: 60m}
`
	p := writeTempYAML(t, "bad.yaml", yaml)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected error for 120m ttl, got nil")
	}
}

func TestLoadRejectsMissingPagerDutyToken(t *testing.T) {
	yaml := `
server: {addr: ":80"}
token_ttl: 60m
providers:
  pagerduty: {api_token: ""}
  jira: {api_token: x}
vault: {addr: "https://v", token_ttl: 60m}
`
	p := writeTempYAML(t, "bad2.yaml", yaml)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected error for missing PD token, got nil")
	}
}

func TestValidateTTLBoundaries(t *testing.T) {
	cases := []struct {
		name string
		ttl  time.Duration
		ok   bool
	}{
		{"zero", 0, false},
		{"negative", -1 * time.Second, false},
		{"one_min", time.Minute, true},
		{"max", models.MaxTTL, true},
		{"over_max", models.MaxTTL + time.Second, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Default()
			c.TokenTTL = tc.ttl
			err := c.Validate()
			if tc.ok && err != nil {
				t.Errorf("expected ok, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Errorf("expected error for ttl %v", tc.ttl)
			}
		})
	}
}

func TestDefaultIsAlwaysValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("Default() must always validate: %v", err)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}