// Package config loads and validates the YAML configuration that drives
// the JIT Access Broker. It deliberately keeps zero global state so it can
// be exercised purely from tests.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/example/jit-access-broker/models"
)

// Config is the top-level configuration object.
type Config struct {
	Server             ServerConfig        `yaml:"server"`
	Providers          ProvidersConfig     `yaml:"providers"`
	Vault              VaultConfig         `yaml:"vault"`
	AWS                AWSConfig           `yaml:"aws"`
	TokenTTL           time.Duration       `yaml:"token_ttl"`
	MaxSessionDuration time.Duration       `yaml:"max_session_duration"`
	WarningBeforeExpiry time.Duration      `yaml:"warning_before_expiry"`
	Notifications      NotificationsConfig `yaml:"notifications"`
	Persistence        PersistenceConfig   `yaml:"persistence"`
	BreakGlass         BreakGlassConfig    `yaml:"break_glass"`
	Slack              SlackConfig         `yaml:"slack"`
}

// SlackConfig controls the optional Slack ChatOps slash command endpoint.
type SlackConfig struct {
	Enabled       bool              `yaml:"enabled"`
	SigningSecret string            `yaml:"signing_secret"`
	BotToken      string            `yaml:"bot_token"`
	UserEmailMap  map[string]string `yaml:"user_email_map"`
}

// NotificationsConfig controls Slack/Teams/CLI expiry notifications.
type NotificationsConfig struct {
	SlackWebhookURL string `yaml:"slack_webhook_url"`
	TeamsWebhookURL string `yaml:"teams_webhook_url"`
	Enabled         bool   `yaml:"enabled"`
}

// ServerConfig controls the HTTP listener.
type ServerConfig struct {
	Addr            string        `yaml:"addr"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
}

// ProvidersConfig holds credentials for the contextual-validation providers.
type ProvidersConfig struct {
	PagerDuty PagerDutyConfig `yaml:"pagerduty"`
	Jira      JiraConfig      `yaml:"jira"`
}

// PagerDutyConfig configures the PagerDuty REST API client.
type PagerDutyConfig struct {
	APIBaseURL string `yaml:"api_base_url"`
	APIToken   string `yaml:"api_token"`
}

// JiraConfig configures the Jira Cloud REST API client.
type JiraConfig struct {
	APIBaseURL string `yaml:"api_base_url"`
	Username   string `yaml:"username"`
	APIToken   string `yaml:"api_token"`
}

// VaultConfig configures the HashiCorp Vault token-issuing target provider.
type VaultConfig struct {
	Addr     string        `yaml:"addr"`
	Token    string        `yaml:"token"`
	TokenTTL time.Duration `yaml:"token_ttl"`
	// MaxTokensPerUser limits how many live tokens a single user may hold.
	MaxTokensPerUser int `yaml:"max_tokens_per_user"`
}

// AWSConfig is an optional STS/IAM target (skeleton implementation).
type AWSConfig struct {
	Region    string `yaml:"region"`
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"`
	RoleARN   string `yaml:"role_arn"`
}

// PersistenceConfig controls the durable state store (crash recovery).
type PersistenceConfig struct {
	Path string `yaml:"path"` // path to the state file (e.g. /var/lib/jit/state.json)
}

// BreakGlassConfig controls the emergency quorum break-glass pathway.
type BreakGlassConfig struct {
	// TrustedApprovers maps approver_id → Ed25519 public key (hex-encoded).
	TrustedApprovers map[string]string `yaml:"trusted_approvers"`
}

// UnmarshalYAML implements yaml.Unmarshaler so duration fields can be
// expressed as human-friendly strings ("60m", "5s") in the YAML file.
func (c *Config) UnmarshalYAML(value *yaml.Node) error {
	type raw struct {
		Server struct {
			Addr            string `yaml:"addr"`
			ShutdownTimeout string `yaml:"shutdown_timeout"`
		} `yaml:"server"`
		Providers          ProvidersConfig     `yaml:"providers"`
		Vault              struct {
			Addr             string `yaml:"addr"`
			Token            string `yaml:"token"`
			TokenTTL         string `yaml:"token_ttl"`
			MaxTokensPerUser int    `yaml:"max_tokens_per_user"`
		} `yaml:"vault"`
		AWS                AWSConfig           `yaml:"aws"`
		TokenTTL           string              `yaml:"token_ttl"`
		MaxSessionDuration string              `yaml:"max_session_duration"`
		WarningBeforeExpiry string             `yaml:"warning_before_expiry"`
		Notifications      NotificationsConfig `yaml:"notifications"`
		Persistence        PersistenceConfig   `yaml:"persistence"`
		BreakGlass         BreakGlassConfig    `yaml:"break_glass"`
		Slack              SlackConfig         `yaml:"slack"`
	}
	var r raw
	if err := value.Decode(&r); err != nil {
		return err
	}

	c.Server.Addr = r.Server.Addr
	if r.Server.ShutdownTimeout != "" {
		d, err := time.ParseDuration(r.Server.ShutdownTimeout)
		if err != nil {
			return fmt.Errorf("server.shutdown_timeout: %w", err)
		}
		c.Server.ShutdownTimeout = d
	}
	c.Providers = r.Providers
	c.Vault.Addr = r.Vault.Addr
	c.Vault.Token = r.Vault.Token
	c.Vault.MaxTokensPerUser = r.Vault.MaxTokensPerUser
	if r.Vault.TokenTTL != "" {
		d, err := time.ParseDuration(r.Vault.TokenTTL)
		if err != nil {
			return fmt.Errorf("vault.token_ttl: %w", err)
		}
		c.Vault.TokenTTL = d
	}
	c.AWS = r.AWS
	if r.TokenTTL != "" {
		d, err := time.ParseDuration(r.TokenTTL)
		if err != nil {
			return fmt.Errorf("token_ttl: %w", err)
		}
		c.TokenTTL = d
	}
	if r.MaxSessionDuration != "" {
		d, err := time.ParseDuration(r.MaxSessionDuration)
		if err != nil {
			return fmt.Errorf("max_session_duration: %w", err)
		}
		c.MaxSessionDuration = d
	}
	if r.WarningBeforeExpiry != "" {
		d, err := time.ParseDuration(r.WarningBeforeExpiry)
		if err != nil {
			return fmt.Errorf("warning_before_expiry: %w", err)
		}
		c.WarningBeforeExpiry = d
	}
	c.Notifications = r.Notifications
	c.Persistence = r.Persistence
	c.BreakGlass = r.BreakGlass
	c.Slack = r.Slack
	return nil
}

// Validate enforces the hard invariants of the system.
func (c *Config) Validate() error {
	if c.Server.Addr == "" {
		return fmt.Errorf("server.addr must be set")
	}
	if c.TokenTTL <= 0 {
		return fmt.Errorf("token_ttl must be > 0")
	}
	if c.TokenTTL > models.MaxTTL {
		return fmt.Errorf("token_ttl %s exceeds hard max %s", c.TokenTTL, models.MaxTTL)
	}
	if c.Vault.Addr == "" {
		return fmt.Errorf("vault.addr must be set")
	}
	if c.Vault.TokenTTL <= 0 || c.Vault.TokenTTL > models.MaxTTL {
		return fmt.Errorf("vault.token_ttl must be in (0, %s]", models.MaxTTL)
	}
	if c.Providers.PagerDuty.APIToken == "" {
		return fmt.Errorf("pagerduty.api_token must be set")
	}
	if c.Providers.Jira.APIToken == "" {
		return fmt.Errorf("jira.api_token must be set")
	}
	// Apply defaults for session ceiling + warning window
	if c.MaxSessionDuration <= 0 {
		c.MaxSessionDuration = models.MaxSessionDuration
	}
	if c.MaxSessionDuration > models.MaxSessionDuration {
		return fmt.Errorf("max_session_duration %s exceeds hardcoded ceiling %s",
			c.MaxSessionDuration, models.MaxSessionDuration)
	}
	if c.WarningBeforeExpiry <= 0 {
		c.WarningBeforeExpiry = models.WarningBeforeExpiry
	}
	return nil
}

// Load reads, parses and validates a YAML config file from disk.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}
	return &c, nil
}

// Default returns a sane in-memory config used by tests and the default
// server boot path when no file is supplied.
func Default() *Config {
	return &Config{
		Server: ServerConfig{
			Addr:            ":8080",
			ShutdownTimeout: 5 * time.Second,
		},
		Providers: ProvidersConfig{
			PagerDuty: PagerDutyConfig{APIBaseURL: "https://api.pagerduty.com", APIToken: "default-disabled"},
			Jira:      JiraConfig{APIBaseURL: "https://example.atlassian.net", APIToken: "default-disabled", Username: "bot@example.com"},
		},
		Vault: VaultConfig{
			Addr:             "https://127.0.0.1:8200",
			TokenTTL:         models.MaxTTL,
			MaxTokensPerUser: 3,
		},
		TokenTTL:            models.MaxTTL,
		MaxSessionDuration:  models.MaxSessionDuration,
		WarningBeforeExpiry: models.WarningBeforeExpiry,
	}
}