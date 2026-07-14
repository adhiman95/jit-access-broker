// jit-access-broker is the main entry point for the JIT Ephemeral Access Broker.
//
// It loads the YAML config, wires the PagerDuty + Jira providers into the
// validation engine, the Vault issuer into the token store, and starts the
// HTTP API server plus the self-destruction worker.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/example/jit-access-broker/api"
	"github.com/example/jit-access-broker/audit"
	"github.com/example/jit-access-broker/auth"
	"github.com/example/jit-access-broker/breakglass"
	"github.com/example/jit-access-broker/config"
	"github.com/example/jit-access-broker/notifier"
	"github.com/example/jit-access-broker/persistence"
	"github.com/example/jit-access-broker/providers"
	"github.com/example/jit-access-broker/retry"
	"github.com/example/jit-access-broker/slack"
	"github.com/example/jit-access-broker/store"
)

func main() {
	configPath := flag.String("config", "", "path to YAML config file (optional)")
	flag.Parse()

	cfg := config.Default()
	if *configPath != "" {
		c, err := config.Load(*configPath)
		if err != nil {
			log.Fatalf("config: %v", err)
		}
		cfg = c
	}

	// --- Audit Logger ---
	auditLog := audit.NewLogger()

	// --- Providers ---
	pdClient := &providers.PagerDutyClient{
		BaseURL:  cfg.Providers.PagerDuty.APIBaseURL,
		APIToken: cfg.Providers.PagerDuty.APIToken,
	}
	jiraClient := &providers.JiraClient{
		BaseURL:  cfg.Providers.Jira.APIBaseURL,
		Username: cfg.Providers.Jira.Username,
		APIToken: cfg.Providers.Jira.APIToken,
	}
	var issuer providers.TokenIssuer
	if cfg.Vault.Token != "" && cfg.Vault.Token != "YOUR_VAULT_ROOT_TOKEN" {
		issuer = &providers.VaultClient{
			Addr:  cfg.Vault.Addr,
			Token: cfg.Vault.Token,
		}
	} else {
		// Demo/fallback issuer so the binary runs without a live Vault.
		issuer = &providers.DemoIssuer{}
		log.Println("WARNING: running with DemoIssuer — no real tokens are issued. Set vault.token + vault.addr for production.")
	}

	// --- Engine ---
	engine := auth.NewEngine(map[string]providers.ContextValidator{
		"pagerduty": pdClient,
		"jira":      jiraClient,
	})

	// --- Token Store + Worker ---
	tokenStore := store.New(issuer)
	tokenStore.SetSessionLimits(cfg.TokenTTL, cfg.MaxSessionDuration, cfg.WarningBeforeExpiry)

	// --- Retry Revoker (production reliability) ---
	revoker := retry.NewRetryRevoker(issuer, auditLog)
	tokenStore.SetRetryRevoker(revoker)

	// --- Audit Logger wiring ---
	tokenStore.SetAuditLogger(auditLog)

	// --- Persistence (SQLite-like file store) ---
	if cfg.Persistence.Path != "" {
		persistStore := persistence.New(cfg.Persistence.Path)
		if err := tokenStore.SetPersistence(persistStore); err != nil {
			log.Printf("WARNING: persistence recovery failed: %v", err)
		} else {
			log.Printf("persistence: state file = %s", cfg.Persistence.Path)
		}
	}

	// --- Break-Glass Manager ---
	var bgManager *breakglass.Manager
	if len(cfg.BreakGlass.TrustedApprovers) > 0 {
		bgManager = breakglass.NewManager(cfg.BreakGlass.TrustedApprovers, issuer, auditLog)
		log.Printf("break-glass: enabled with %d trusted approver(s), quorum=%d",
			len(cfg.BreakGlass.TrustedApprovers), breakglass.QuorumRequired)
	} else {
		log.Println("break-glass: DISABLED (no trusted_approvers configured)")
	}

	// --- Notifier wiring ---
	var multi notifier.MultiNotifier
	if cfg.Notifications.Enabled {
		if cfg.Notifications.SlackWebhookURL != "" {
			multi.Children = append(multi.Children, &notifier.SlackNotifier{WebhookURL: cfg.Notifications.SlackWebhookURL})
		}
		if cfg.Notifications.TeamsWebhookURL != "" {
			multi.Children = append(multi.Children, &notifier.TeamsNotifier{WebhookURL: cfg.Notifications.TeamsWebhookURL})
		}
	}
	// Always include the log notifier so CLI users see warnings
	multi.Children = append(multi.Children, notifier.LogNotifier{})
	if len(multi.Children) > 0 {
		tokenStore.SetNotifier(&multi)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tokenStore.Run(ctx)

	// --- HTTP Server ---
	srv := api.NewServer(engine, issuer, tokenStore, cfg.TokenTTL)
	srv.SetAuditLogger(auditLog)
	if bgManager != nil {
		srv.SetBreakGlassManager(bgManager)
	}
	if cfg.Slack.Enabled {
		slackHandler := &slack.Handler{
			Engine:        engine,
			Issuer:        issuer,
			Store:         tokenStore,
			TTL:           cfg.TokenTTL,
			SigningSecret: cfg.Slack.SigningSecret,
			UserEmailMap:  cfg.Slack.UserEmailMap,
			BotToken:      cfg.Slack.BotToken,
		}
		srv.SetSlackHandler(slackHandler)
		log.Printf("slack: ChatOps enabled — mount /slack/command as your slash command URL")
	}
	httpSrv := &http.Server{
		Addr:    cfg.Server.Addr,
		Handler: srv.Router(),
	}

	// --- Graceful Shutdown ---
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("shutting down...")
		cancel()
		// Persist final state before exit
		_ = tokenStore.PersistAll()
		shutCtx, shutCancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
		defer shutCancel()
		_ = httpSrv.Shutdown(shutCtx)
	}()

	fmt.Printf("JIT Access Broker listening on %s (TTL=%s, max session=%s, warning=%s)\n",
		cfg.Server.Addr, cfg.TokenTTL, cfg.MaxSessionDuration, cfg.WarningBeforeExpiry)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server: %v", err)
	}
}