# Ferropost

Open-source email marketing platform & mail server, derived from BillionMail (AGPL-3.0). Handles bulk sending, campaigns, contact management, warmup, and analytics. The Go core (`core/`) is being replaced by the Rust core (`core-rs/`) one domain at a time; internal names such as the `billionmail` database, `.env` keys and `/opt/billionmail` paths stay until that is finished.

## Project Structure

```
core/
├── internal/
│   ├── cmd/            # CLI entry points
│   ├── controller/     # HTTP handlers (16+ domains)
│   ├── service/        # Business logic (batch_mail, domains, rbac, maillog_stat, warmup, contact, etc.)
│   ├── dao/            # Data access layer
│   ├── model/entity/   # ORM entities
│   └── consts/         # Constants
├── api/                # API route definitions
├── frontend/src/
│   ├── views/          # Page components
│   ├── components/     # Reusable UI components
│   ├── store/          # Pinia store modules
│   ├── api/modules/    # API client modules
│   ├── router/         # Vue Router + module routes
│   ├── hooks/          # Composables
│   ├── utils/          # Utilities (base, data, time, storage)
│   ├── features/       # Feature-specific components (EmailEditor)
│   └── i18n/           # Internationalization (en, zh, ja)
├── template/           # Email templates
└── manifest/           # Config/deployment
core-rs/                # Rust core replacing core/ domain by domain (see core-rs/README.md)
├── crates/domain/      # Pure types and rules, no IO
├── crates/common/      # Config, shared .env reader, i18n
├── crates/store/       # Postgres (sqlx) + Redis (fred) queries on the Go schema
├── crates/api/         # axum: edge policies, auth/RBAC, native routes, proxy to Go
└── crates/server/      # ferropost binary: listeners, TLS/SNI
conf/                   # Mail service configs (postfix, dovecot, rspamd, redis)
Dockerfiles/            # Container definitions
```

## Stack

- **Backend:** Go 1.22, GoFrame v2, PostgreSQL, Redis
- **Backend (migration in progress):** Rust (edition 2024), axum, sqlx, fred. `ferropost` owns the public ports and proxies unported routes to Go running with `FERROPOST_GO_INTERNAL_ADDR`
- **Frontend:** Vue 3, TypeScript, Pinia, Naive UI, Vitest, pnpm
- **Mail:** Postfix, Dovecot, Rspamd
- **Deploy:** Docker Compose

## Organization Rules

- Controllers → `core/internal/controller/`, one dir per domain
- Services → `core/internal/service/`, one dir per domain
- API routes → `core/api/`, one dir per domain
- Frontend views → `core/frontend/src/views/`, one dir per feature
- Tests → next to source files (`*_test.go`, `*.test.ts`)
- Single responsibility per file, descriptive names

## Code Quality

After editing ANY file, run:

```bash
# Go
cd core && go vet ./... && gofmt -l .

# Frontend
cd core/frontend && pnpm run lint

# Rust
cd core-rs && cargo fmt --check && cargo clippy --all-targets
```

Fix ALL errors before continuing.

## Testing

```bash
# Go (short mode, no DB required)
cd core && go test -count=1 -short ./internal/service/...

# Frontend
cd core/frontend && pnpm test

# Rust (unit; e2e needs FERROPOST_TEST_DATABASE_URL/FERROPOST_TEST_REDIS_URL, see core-rs/README.md)
cd core-rs && cargo test

# Both
cd core && go test -count=1 -short ./internal/service/... && cd frontend && pnpm test
```

## Bug Memory Rules

- NEVER use bare domain for mail infrastructure (DNS, certs, DKIM, dedicated IPs). Always use `public.FormatMX(domain)` to get the mail hostname (e.g., `mail.example.com`).
- When adding new controllers, add the module name to the RBAC `modules` list in `core/internal/service/middlewares/rbac.go` (and `MODULES` in `core-rs/crates/domain/src/rbac.rs`).
- Rust mail infrastructure: resolve hostnames with `ferropost_store::domains::mail_hostname` (DB `a_record`, then `ferropost_domain::mail::mx_hostname_fallback`), never the bare domain.
- When porting a route to Rust, register every HTTP method Go serves on that path, keep the `{success, code, msg, data}` envelope (errors on HTTP 200), and move the domain's timers out of Go in the same change.

## Commands

- `/test` - Run full test suite
- `/fix` - Lint + typecheck + auto-fix with parallel agents
- `/commit` - Quality checks + AI commit + push
- `/update-app` - Update deps + fix deprecations
