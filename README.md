# Trimly ShortLink Platform

<!-- sync:description -->
Trimly Platform is a high-performance, developer-first URL shortener built with Go and PostgreSQL. It features plan-based quota enforcement, fast-path public redirects, team workspaces, marketing UTM tracking, platform administration, and B2B API Key integration with rate limiting.
<!-- end-sync:description -->

---

## ⚡ Quick Start & Development

### 1. Prerequisites
- **Go:** 1.24 or later
- **Docker & Docker Compose** (for local PostgreSQL 16 & MailHog)

### 2. Run Local Infrastructure
```bash
docker-compose up -d
```

### 3. Run Application API Server
```bash
go run ./cmd/api
```
The server will start at `http://localhost:8080`.

### 4. Execute Test Suite
```bash
go test -v -race ./...
```

---

## 📚 Documentation

For complete developer guidelines, directory structures, build instructions, and architecture decisions, please refer to the Developer Handbook:
- 📄 **Developer Handbook:** [project_context.md](project_context.md)
