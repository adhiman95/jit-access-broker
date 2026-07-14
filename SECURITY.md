# Security Policy

## 🔒 Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in this project, please report it responsibly:

### Preferred Method: GitHub Private Vulnerability Reporting

1. Go to the **Security** tab of this repository
2. Click **Report a vulnerability**
3. Provide a detailed description of the issue and steps to reproduce

### Alternative: Email

Send details to: **security@your-domain.com**

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

| Step | Target |
|------|--------|
| Acknowledge receipt | Within 48 hours |
| Initial assessment | Within 7 days |
| Fix or mitigation | Within 30 days (severity-dependent) |
| Public disclosure | After fix is released, coordinated with reporter |

## 🛡️ Security Measures in This Project

This project implements the following security controls:

| Control | Implementation |
|---------|---------------|
| **No standing access** | All tokens self-destruct at TTL (max 60 min) |
| **Contextual authorization** | Requests validated against PagerDuty/Jira assignee + status |
| **Idempotent revocation** | Retry with exponential backoff ensures tokens are revoked |
| **Break-glass quorum** | Emergency access requires 2-of-3 Ed25519 signatures |
| **Audit trail** | Every grant and revocation logged as structured JSON |
| **Crash recovery** | Missed expirations are revoked on restart |
| **Session ceiling** | Hard cap on total session duration across extensions |
| **Secret hygiene** | `.gitignore` prevents accidental secret commits |

## ⚠️ Production Deployment Security Checklist

Before deploying to production, ensure:

- [ ] TLS termination is configured (reverse proxy or native TLS)
- [ ] API endpoints require authentication (mTLS, OAuth2, or API key)
- [ ] `config.local.yaml` (with real secrets) is NEVER committed
- [ ] Vault token has least-privilege policies (not root token)
- [ ] PagerDuty/Jira API tokens are read-scoped
- [ ] Audit log output is shipped to a SIEM (Splunk, ELK, Datadog)
- [ ] The persistence file path is on encrypted storage
- [ ] Break-glass private keys are distributed offline to approvers only