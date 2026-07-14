# 🔐 JIT Ephemeral Access Broker

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Slack](https://img.shields.io/badge/ChatOps-Slack-4A154B?logo=slack)]()
[![K8s](https://img.shields.io/badge/Helm-Chart-326CE5?logo=kubernetes)]()
[![AWS](https://img.shields.io/badge/Terraform-ECS_Fargate-7B42BC?logo=terraform)]()

A lightweight, production-ready **Just-in-Time (JIT) Ephemeral Access Broker** written in Go. It intercepts developer production access requests, cross-references them with external operational context (PagerDuty / Jira), and automatically provisions **short-lived, self-destructing** credentials against HashiCorp Vault, AWS IAM, or Kubernetes.

> **No standing access. Ever.** Every token self-destructs in exactly 60 minutes.

---

## 📑 Table of Contents

- [What Problems Does This Solve?](#-what-problems-does-this-solve)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [API Reference](#-api-reference)
- [Slack ChatOps](#-slack-chatops)
- [CLI Reference](#-cli-reference)
- [Architecture](#-architecture)
- [Deployment](#-deployment)
- [Production Hardening Checklist](#-production-hardening-checklist)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🤔 What Problems Does This Solve?

| Problem | How This Project Fixes It |
|---------|---------------------------|
| **Standing privileged access** | Every token self-destructs in 60 minutes — no permanent credentials. |
| **Untraceable production changes** | Every request is tied to a verifiable PagerDuty incident or Jira ticket. The broker verifies the requester is the **assigned engineer** and the ticket is **actively being worked**. |
| **Credential sprawl** | Tokens are auto-revoked at TTL expiry by a background worker using a priority queue. Zero manual cleanup. |
| **Compliance (SOC2, PCI-DSS, ISO 27001)** | Every grant is logged with: who, what resource, what justification, when issued, when auto-expired. Structured JSON audit log to stdout. |

---

## 🚀 Quick Start

### Prerequisites
- **Go 1.21+** → [download here](https://go.dev/dl/)

### Build

**Linux / macOS:**
```bash
git clone https://github.com/adhiman95/jit-access-broker.git
cd jit-access-broker

# Build the server binary
go build -o bin/jit-broker .

# Build the CLI tool
go build -o bin/jitctl ./cmd/jitctl
```

**Windows:**
```cmd
git clone https://github.com/adhiman95/jit-access-broker.git
cd jit-access-broker

go build -o bin\jit-broker.exe .
go build -o bin\jitctl.exe .\cmd\jitctl
```

### Start the Server

```bash
./bin/jit-broker --config config.yaml
```

Test it:
```bash
curl http://localhost:8080/healthz
# → {"status":"ok"}
```

> The sample `config.yaml` uses placeholder values. To grant real tokens, see [Configuration](#-configuration).

### Docker (includes Vault)

```bash
cp config.yaml config.local.yaml
# Edit config.local.yaml with your credentials

docker compose up --build
```

Spins up:
- **JIT Broker** on `http://localhost:8080`
- **HashiCorp Vault** (dev mode) on `http://localhost:8200` (token: `dev-token`)

> **Note:** Dev mode Vault is in-memory and auto-unsealed. Use a properly initialized Vault cluster for production.

---

## 🔧 Configuration

Create a local config with your real credentials:

```bash
cp config.yaml config.local.yaml
```

> `config.local.yaml` is in `.gitignore` — secrets will never be committed.

Full `config.yaml` reference:

```yaml
# ──────────────────────────────────────────
# SERVER
# ──────────────────────────────────────────
server:
  addr: ":8080"              # listen address
  shutdown_timeout: "5s"     # graceful shutdown wait

# ──────────────────────────────────────────
# TOKEN LIFECYCLE (hardcoded ceiling = 60 min)
# ──────────────────────────────────────────
token_ttl: "60m"             # per-token TTL (max 60m, enforced in code)
max_session_duration: "4h"   # absolute ceiling across ALL extensions
warning_before_expiry: "15m" # fire "expiring soon" notification this early

# ──────────────────────────────────────────
# CONTEXTUAL VALIDATION PROVIDERS
# ──────────────────────────────────────────
providers:
  pagerduty:
    api_base_url: "https://api.pagerduty.com"
    api_token: "YOUR_PAGERDUTY_API_TOKEN"    # ← REPLACE

  jira:
    api_base_url: "https://your-domain.atlassian.net"
    username: "bot@your-domain.com"          # ← REPLACE
    api_token: "YOUR_JIRA_API_TOKEN"         # ← REPLACE

# ──────────────────────────────────────────
# TOKEN ISSUING PROVIDER
# ──────────────────────────────────────────
vault:
  addr: "https://127.0.0.1:8200"             # ← REPLACE
  token: "YOUR_VAULT_ROOT_TOKEN"             # ← REPLACE
  token_ttl: "60m"
  max_tokens_per_user: 3

# AWS IAM (optional)
aws:
  region: "us-east-1"
  access_key: ""
  secret_key: ""
  role_arn: ""

# ──────────────────────────────────────────
# EXPIRY NOTIFICATIONS (optional)
# ──────────────────────────────────────────
notifications:
  enabled: false
  slack_webhook_url: ""
  teams_webhook_url: ""

# ──────────────────────────────────────────
# CRASH RECOVERY / PERSISTENCE (optional)
# ──────────────────────────────────────────
persistence:
  path: ""    # e.g. "/var/lib/jit-access-broker/state.json"

# ──────────────────────────────────────────
# EMERGENCY BREAK-GLASS (2-of-3 quorum)
# ──────────────────────────────────────────
break_glass:
  trusted_approvers:
    alice: ""    # ← REPLACE with hex Ed25519 public key
    bob: ""      # ← REPLACE with hex Ed25519 public key
    carol: ""    # ← REPLACE with hex Ed25519 public key
```

### Credentials Reference

| Credential | How to Get It |
|---|---|
| **PagerDuty API Token** | PagerDuty → Integrations → API Access Keys → Create |
| **Jira API Token** | https://id.atlassian.com/manage-profile/security/api-tokens |
| **Vault Token** | `vault token create -policy=your-policy` |
| **Break-Glass Keys** | `./bin/jitctl genkeys --approver alice` (generates Ed25519 keypair) |

---

## 🌐 API Reference

### Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/v1/access/request` | Request ephemeral access (validates against PagerDuty/Jira) |
| `POST` | `/api/v1/access/extend` | Extend a token's TTL (re-validates context, respects session ceiling) |
| `POST` | `/api/v1/access/breakglass/activate` | Emergency access (requires 2-of-3 Ed25519 signatures) |
| `POST` | `/api/v1/access/revoke/:id` | Manually revoke a token |
| `GET` | `/api/v1/access/tokens` | List all live tokens |
| `POST` | `/slack/command` | **Slack slash command** `/jit <resource> <pagerduty|jira> <ref>` |
| `GET` | `/healthz` | Liveness probe |

### Request Access

```bash
curl -X POST http://localhost:8080/api/v1/access/request \
  -H "Content-Type: application/json" \
  -d '{
    "user_identity": "alice@example.com",
    "resource": "prod-db-readonly",
    "justification_type": "pagerduty",
    "justification_ref": "Q3ABC123"
  }'
```

**Success (200 OK):**
```json
{
  "granted": true,
  "token": "hvs.AABBCCDD...",
  "token_id": "tok_abc123",
  "resource": "prod-db-readonly",
  "issued_at": "2026-07-13T23:00:00Z",
  "expires_at": "2026-07-14T00:00:00Z",
  "ttl_seconds": 3600
}
```

**Failure (403 Forbidden):**
```json
{
  "error": "context_validation_failed",
  "reason": "user bob@example.com is not an assignee of incident Q3ABC123",
  "status": 403
}
```

### Extend Access

```bash
curl -X POST http://localhost:8080/api/v1/access/extend \
  -H "Content-Type: application/json" \
  -d '{
    "token_id": "tok_abc123",
    "user_identity": "alice@example.com",
    "justification_type": "pagerduty",
    "justification_ref": "Q3ABC123"
  }'
```

### Break-Glass (Emergency)

When PagerDuty/Jira are down, 2 of 3 trusted approvers can sign a request:

```bash
curl -X POST http://localhost:8080/api/v1/access/breakglass \
  -H "Content-Type: application/json" \
  -d '{
    "user": "alice@example.com",
    "resource": "prod-vault",
    "reason": "PagerDuty is down, need emergency access",
    "ttl_minutes": 30,
    "signatures": [
      {"approver_id": "alice", "signature": "hex_sig_1..."},
      {"approver_id": "bob", "signature": "hex_sig_2..."}
    ]
  }'
```

---

## 💬 Slack ChatOps

Enable the `/jit` slash command so engineers can request access **directly from Slack** — no CLI or curl needed.

### Setup

1. **Create a Slack App** → [api.slack.com/apps](https://api.slack.com/apps) → *Create New App*
2. **Add Slash Command:**
   - Command: `/jit`
   - Request URL: `https://your-broker-host/slack/command`
3. **Required scopes:** `chat:write`, `users:read`, `users:read.email`
4. **Enable in config:**

```yaml
slack:
  enabled: true
  signing_secret: "YOUR_SLACK_SIGNING_SECRET"
  bot_token: "xoxb-YOUR-BOT-TOKEN"
  user_email_map:
    "U12345": "alice@example.com"    # Slack user ID → PagerDuty/Jira email
    "U67890": "bob@example.com"
```

### Usage

```
/jit prod-db-readonly pagerduty Q3ABC123
```

**Success response:**
> ✅ **Access granted** to `prod-db-readonly`
> 🔑 Token: `hvs.AABB...` (expires in 60 min)
> 📋 Justification: PagerDuty incident Q3ABC123

**Denied response:**
> ❌ **Access denied**: You are not assigned to incident Q3ABC123

---

## 🖥️ CLI Reference

```bash
# Request access
./bin/jitctl request \
  --user "alice@example.com" \
  --resource "prod-db-readonly" \
  --type pagerduty \
  --ref "Q3ABC123"

# List active tokens
./bin/jitctl list

# Extend a token
./bin/jitctl extend \
  --id "tok_abc123" \
  --user "alice@example.com" \
  --type pagerduty \
  --ref "Q3ABC123"

# Revoke a token
./bin/jitctl revoke --id "tok_abc123"

# Generate Ed25519 keypair for break-glass approvers
./bin/jitctl genkeys --approver alice
```

---

## 🏗️ Architecture

```
            ┌───────────────┐   POST /api/v1/access/request
 developer  │   jitctl CLI  │─────────────────────────────┐
 ──────────►│  (or curl)    │                             ▼
            └───────────────┘                  ┌─────────────────────┐
                                               │   api.Server (HTTP) │
                                               └──────────┬──────────┘
                                                          │
                                              ┌───────────▼───────────┐
                                              │  auth.Engine (validate)│
                                              └───┬───────────────┬───┘
                                  PagerDuty └────┘               └────► Jira
                                   (assignee+status)         (assignee+status)
                                                          │
                                              ┌───────────▼───────────┐
                                              │ providers.Vault.Issue │  ◄── TTL = 60m max
                                              └───────────┬───────────┘
                                                          │
                                              ┌───────────▼───────────┐
                                              │  store.Store          │
                                              │  + min-heap priority Q│
                                              │  + self-destruct worker│ ──► Vault.Revoke @ TTL
                                              │  + audit logger       │
                                              │  + retry revoker      │
                                              │  + persistence        │
                                              └───────────────────────┘
```

### Security Guarantees (Enforced in Code)

| Rule | How It's Enforced |
|------|-------------------|
| TTL ≤ 60 min | `models.MaxTTL` constant + `config.Validate()` |
| User must own incident/ticket | `auth.Engine` + provider `Validate()` |
| Status must be active | Provider `Validate()` checks `acknowledged` / `In Progress` |
| Tokens auto-revoke at TTL | `store.Store.Run()` worker + min-heap |
| Revoke is idempotent | `Vault.Revoke()` handles nil/empty safely |
| Session ceiling enforced | `MaxSessionDuration` (4h) clamps extensions |
| Break-glass needs 2-of-3 | Ed25519 signature quorum + dedup |

---

## ✅ Production Hardening Checklist

- [ ] **TLS termination** — reverse proxy (nginx/traefik) or `http.Server{TLSConfig}`
- [ ] **Authentication middleware** — mTLS, OAuth2, or API key on all endpoints
- [ ] **Persistent token store** — Redis/PostgreSQL instead of in-memory map
- [ ] **Metrics endpoint** — Prometheus `/metrics` for observability
- [ ] **Real AWS STS** — implement `providers/aws.go` (currently a skeleton)
- [ ] **Real Kubernetes RBAC** — add a k8s service account provider
- [ ] **Rate limiting** — per-user request throttling
- [ ] **Audit log persistence** — ship stdout JSON to Splunk/ELK/Datadog
- [ ] **Secrets management** — load API tokens from Vault/AWS Secrets Manager instead of YAML
- [ ] **Horizontal scaling** — the in-memory store is single-instance; use Redis for HA

---

## 🚢 Deployment

### Option 1: Docker

```bash
docker build -t jit-access-broker .
docker run -p 8080:8080 -v $(pwd)/config.yaml:/app/config.yaml jit-access-broker
```

### Option 2: Helm Chart (Kubernetes)

```bash
helm install jit-access-broker ./deploy/helm/jit-access-broker \
  --set secrets.vaultToken="hvs.YOUR_TOKEN" \
  --set secrets.pagerdutyApiToken="YOUR_PD_TOKEN" \
  --set secrets.jiraApiToken="YOUR_JIRA_TOKEN" \
  --set secrets.jiraUsername="bot@example.com"
```

Includes: Deployment, Service, Secret, PVC (persistence), HPA (autoscaling), health probes, and security context (non-root, read-only FS, drop ALL capabilities).

### Option 3: Terraform (AWS ECS Fargate)

```bash
cd deploy/terraform
terraform init

terraform apply \
  -var="vault_addr=https://vault.internal:8200" \
  -var="vault_token=hvs.YOUR_TOKEN" \
  -var="pagerduty_api_token=YOUR_PD_TOKEN" \
  -var="jira_api_token=YOUR_JIRA_TOKEN" \
  -var="jira_username=bot@example.com"
```

Outputs the ALB DNS name, health check URL, and Slack command URL. Secrets are stored in AWS Secrets Manager and injected as environment variables.

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Build and verify (`go build ./...`)
4. Commit your changes (`git commit -m 'Add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.