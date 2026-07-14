# Contributing to JIT Access Broker

First off, thank you for considering contributing! 🎉 This project aims to make production access safer for everyone.

## 🚀 Quick Start for Contributors

### Prerequisites
- **Go 1.21+** — [Install here](https://go.dev/dl/)
- **Git** — [Install here](https://git-scm.com/downloads)
- A GitHub account

### Setup (5 minutes)

```bash
# 1. Fork the repo on GitHub (click the "Fork" button)

# 2. Clone YOUR fork
git clone https://github.com/YOUR_USERNAME/jit-access-broker.git
cd jit-access-broker

# 3. Add the upstream remote
git remote add upstream https://github.com/ORIGINAL_AUTHOR/jit-access-broker.git

# 4. Create a feature branch
git checkout -b feature/my-awesome-feature

# 5. Run tests to make sure everything works
go test ./... -v -cover
```

## 🧒 Development Workflow

1. **Make your changes** — write clean, tested code
2. **Run tests** — `go test ./... -v -cover`
3. **Add tests** for any new functionality
4. **Commit** — use clear commit messages:
   ```bash
   git commit -m "feat: add Kubernetes RBAC provider"
   git commit -m "fix: handle nil context in validation engine"
   git commit -m "docs: add AWS deployment guide"
   ```
5. **Push** to your fork:
   ```bash
   git push origin feature/my-awesome-feature
   ```
6. **Open a Pull Request** on GitHub

## 📋 Pull Request Checklist

Before submitting a PR, make sure:
- [ ] You've added tests for any new code
- [ ] Code follows Go conventions (`gofmt`, `go vet`)
- [ ] No secrets/passwords/tokens in the code
- [ ] `config.local.yaml` is NOT committed (it's in `.gitignore`)
- [ ] Documentation updated if needed

## 🎯 Areas Where We Need Help

| Area | Difficulty | Description |
|------|-----------|-------------|
| AWS STS provider | 🟡 Medium | Complete the skeleton in `providers/aws.go` |
| Kubernetes RBAC | 🟡 Medium | Add a k8s ServiceAccount token provider |
| Persistent storage | 🟠 Hard | Add Redis/PostgreSQL backing for the token store |
| Web UI dashboard | 🟢 Easy | A simple React/Vue dashboard on top of the API |
| Slack bot integration | 🟢 Easy | A Slack bot that calls the API |
| Metrics (Prometheus) | 🟡 Medium | Add `/metrics` endpoint |
| Structured logging | 🟢 Easy | Replace placeholder logging with zerolog/zap |
| Terraform provider | 🟠 Hard | Allow Terraform to manage JIT policies |

## 🐛 Reporting Bugs

Open a [GitHub Issue](../../issues) with:
1. **What happened** (error message, unexpected behavior)
2. **What you expected** to happen
3. **Steps to reproduce** (commands you ran)
4. **Your environment** (OS, Go version, config — **without secrets!**)

## 💡 Suggesting Features

Open a [GitHub Issue](../../issues) with the `enhancement` label. Describe:
1. **The problem** you're trying to solve
2. **Your proposed solution**
3. **Alternatives** you've considered

## 📜 Code Style

- Follow [Effective Go](https://go.dev/doc/effective_go)
- Run `gofmt -w .` before committing
- Run `go vet ./...` before committing
- Keep functions small and focused
- Every public function needs a doc comment

## 📜 License

By contributing, you agree that your contributions are licensed under the MIT License.

## ❓ Questions?

Open a [GitHub Discussion](../../discussions) — we're happy to help!