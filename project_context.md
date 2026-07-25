# Project Context: Trimly ShortLink Platform

<!-- sync:description -->
Trimly Platform is a high-performance, developer-first URL shortener built with Go and PostgreSQL. It features plan-based quota enforcement, fast-path public redirects, team workspaces, marketing UTM tracking, platform administration, and B2B API Key integration with rate limiting.
<!-- end-sync:description -->

## Tech Stack
- **Language & Runtime:** Go 1.24+ (Standard Library HTTP Router)
- **Database:** PostgreSQL 16 Alpine (`pgx/v5` Connection Pool)
- **Rate Limiting & Concurrency:** In-Memory `golang.org/x/time/rate`, Buffered Channels, Atomic DB Transactions
- **Containerization & Dev Env:** Docker Compose (PostgreSQL & MailHog)
- **CI/CD:** GitHub Actions (`.github/workflows/ci.yml`)

## Core Directory Structure
```text
.
├── cmd/
│   └── api/               # Main HTTP application entrypoint & routing wiring
├── internal/
│   ├── admin/             # Platform admin management & domain blacklist
│   ├── apikey/            # B2B API Key generation, auth middleware & rate limiting
│   ├── auth/              # Stateful session auth, password hashing & email verification
│   ├── config/            # Environment configuration loader
│   ├── link/              # Shortlink creation, atomic quota locking & fast public redirect
│   ├── pkg/               # Common HTTP response helpers & email adapters
│   └── workspace/         # Team workspace management & RBAC matrix
├── migrations/            # SQL migration scripts (00001_init_schema & 00002_add_api_keys)
├── kiro-task/             # SDLC task specifications, PRD, RFC & Review reports
├── docker-compose.yml     # Local dev setup (Postgres 16 + MailHog)
└── project_context.md     # Core developer handbook & architecture decisions
```

## Development Commands
- **Start Local Infra:** `docker-compose up -d`
- **Run Application:** `go run ./cmd/api`
- **Build Binary:** `go build -v ./cmd/api`
- **Run Unit Tests:** `go test -v -race ./...`

## Architecture Decisions
- **Database-Driven Atomic Quotas (No Redis):** Active link quota (Free plan limit: 10 active links) and B2B daily quota (5,000 req/day) are enforced directly in PostgreSQL via `SELECT ... FOR UPDATE` row locks and `ON CONFLICT DO UPDATE` counters.
- **In-Memory Rate Limiting:** B2B minute rate limiting (60 req/min) uses Go's standard `golang.org/x/time/rate` with a `sync.RWMutex` map. This eliminates external Redis cluster dependencies for MVP.
- **Async High-Throughput Click Logger:** Public redirects (`GET /r/{slug}`) respond immediately (<20ms) and dispatch click events to a buffered in-memory Go channel (5,000 buffer size) processed by background workers.
- **Stateless API Keys & Stateful Web Sessions:** Web dashboard uses HTTP-only stateful session tokens (SHA-256 digested in DB). B2B API Key integration uses CSPRNG secrets hashed with SHA-256 (plaintext visible only once on creation).

## Status & Ongoing Work
- [x] **Rilis 1 (MVP):** Auth, Plan Quota Enforcement, Redirect, Workspaces, UTM Tracking, Minimal Admin.
- [x] **Rilis 2 (B2B API Access):** API Keys Management, In-Memory Minute Rate Limiting (60/min), Daily Quota Enforcement (5,000/day), Usage Dashboard.
- [ ] **Rilis 3 (Next):** Link-in-Bio Public Profiles (`/u/username`) & Click Milestone Email Notifications.
