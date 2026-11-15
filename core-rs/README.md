# Ferropost core (`core-rs`)

Ferropost is an email marketing platform and mail server derived from
[BillionMail](https://github.com/aaPanel/BillionMail) and licensed, like it,
under AGPL-3.0. `core-rs` is the Rust core replacing the Go core (`../core`)
one domain at a time.

The `ferropost` binary is the public front door: it terminates HTTP/HTTPS on
the console ports, serves the routes already ported to Rust, and proxies
everything else to the Go core, which runs on a private address. The Vue frontend, the database schema and the
API contract stay unchanged until the Go side is gone.

```
browser ─► ferropost :80/:443 ─┬─► native route (Rust)  ─► Postgres / Redis
                                    └─► fallback proxy ─► Go core 127.0.0.1:8181 (internal mode)
```

Every request first passes the **edge** (`crates/api/src/edge.rs`). It resolves
the client IP, strips `WEB_BASE_PATH`, enforces the IP whitelist and the safe
entrance (SafePath), and writes the fail2ban access log for requests answered
in Rust.

## Layout

| Crate | Purpose |
|---|---|
| `crates/domain` | Types and pure rules (RBAC path mapping, paging, web paths, mail naming). No IO. |
| `crates/common` | `Config`, the shared `.env` reader, i18n (Go language packs). |
| `crates/store` | Postgres (sqlx) and Redis (fred) queries against the Go schema. |
| `crates/api` | axum app: edge, JWT auth, RBAC, response envelope, Go proxy, native routes. |
| `crates/server` | `ferropost` binary: listeners, TLS/SNI certificates, graceful shutdown. |

## Ported so far

| Route | Notes |
|---|---|
| `/api/email_template/*` (all 8 routes) | Unique names decided by the constraint; `copy` picks the next free `_bak` name; deleting a missing template is a 404 (Go crashed); the content check ignores void elements such as `<br>`. |
| `/api/operation_log/*` (all 4 routes) | Usernames by join. Output logs are read backwards from the end, so a page costs only the lines returned and long lines no longer drop a whole file. |
| `/api/tags/*` (all 6 routes) | List: one query with a join instead of N+1 group lookups, literal keyword match. Writes: the unique constraint decides duplicates; bulk tagging is one all-or-nothing statement and matches addresses case-insensitively. |

Everything else is served by Go through the proxy.

## Configuration

Shared settings come from the BillionMail `.env` (`DBPASS`, `REDISPASS`,
`REDISDB`, `HTTP_PORT`, `HTTPS_PORT`, `SafePath`, `IP_WHITELIST_ENABLE`,
`WEB_BASE_PATH`). Changes to `.env` take effect within about 2 seconds,
without a restart. Settings specific to Rust use `FERROPOST_*` process variables:

| Variable | Default | Purpose |
|---|---|---|
| `FERROPOST_ROOT` | current dir | Core directory (`languages/`, `public/`, `logs/`) |
| `FERROPOST_ENV_FILE` | `$FERROPOST_ROOT/../.env` | Shared env file |
| `FERROPOST_GO_UPSTREAM` | `http://127.0.0.1:8181` | Go core in internal mode |
| `FERROPOST_DATABASE_URL` | unix socket `../postgresql-socket` | Override for development |
| `FERROPOST_REDIS_URL` | `redis:6379` (container) / `127.0.0.1:26379` | Override for development |
| `FERROPOST_HTTP_PORT` / `FERROPOST_HTTPS_PORT` | `.env` values, then 80/443 | Listener ports |
| `FERROPOST_SSL_DIR` | `/etc/ssl/mail` | Default and per-domain certificates |
| `FERROPOST_TRUSTED_PROXIES` | none | CIDRs allowed to set `X-Forwarded-For` (e.g. a reverse proxy in front) |
| `FERROPOST_SERVER_IP` | looked up online | Public IP always allowed by the whitelist |
| `FERROPOST_JWT_SECRET` | `DBPASS`+`REDISPASS` | Must match Go's `jwt.secret` if that is set |
| `FERROPOST_ACCESS_LOG_DIR` | `$FERROPOST_ROOT/logs` | fail2ban access log directory |
| `RUST_LOG` | `info` | Log filter |

The Go core enters internal mode when `FERROPOST_GO_INTERNAL_ADDR` is set. It then
listens on that address over plain HTTP and leaves TLS and the safe entrance
to Rust. Unset, Go behaves exactly as before.

## Develop and test

```bash
cd core-rs
cargo fmt --check && cargo clippy --all-targets   # must be warning-free
cargo test                                        # unit tests, no services needed

# End-to-end tests against real Postgres/Redis (schema is recreated):
docker run -d --rm --name bmrs-test-pg -e POSTGRES_PASSWORD=test -e POSTGRES_USER=billionmail \
  -e POSTGRES_DB=billionmail -p 127.0.0.1:55432:5432 postgres:17-alpine
docker run -d --rm --name bmrs-test-redis -p 127.0.0.1:56379:6379 redis:7-alpine --requirepass test
FERROPOST_TEST_DATABASE_URL=postgres://billionmail:test@127.0.0.1:55432/billionmail \
FERROPOST_TEST_REDIS_URL=redis://:test@127.0.0.1:56379/1 cargo test -p ferropost-api --tests
```

## Build and deploy

`sh core-rs/build.sh [all|x86|arm]` builds static musl binaries in Docker and
writes `core/ferropost-<arch>`, next to the Go binaries from
`core/go-build.sh`. The core image copies both. supervisord runs Go with
`FERROPOST_GO_INTERNAL_ADDR=127.0.0.1:8181` and `ferropost` on the public ports.

**Rollback:** remove the `environment=` line from `[program:core]` and the
`[program:ferropost]` block in `Dockerfiles/core/supervisord.conf`. Go then
owns the ports again.

## Porting a domain

1. Read the Go controller (`core/internal/controller/<domain>`) and the API
   definition (`core/api/<domain>/v1`). Note the paths, methods, defaults,
   validation and the exact JSON shape.
2. Put pure rules in `domain`, queries in `store`, and handlers in
   `api/src/routes/<domain>.rs`. Register them in `routes::router` under the
   same paths. Register **every** method Go serves on a path, otherwise axum
   answers 405 instead of proxying.
3. Keep the envelope: success is `{"success": true, "code": 0, ...}`. Errors use
   HTTP 200 with `code` 401/403/412/500, because the frontend reads the body only.
4. Messages go through `state.i18n.tr(&lang, "<English text>", &[...])` with
   the same English text as Go, so the existing language packs still apply.
5. Move the domain's background jobs (`core/internal/service/timers`) with it,
   and switch them off in Go in the same change.
6. Record writes with the `Audit` extractor using Go's log text, so the
   operation log reads the same.
7. Add unit tests for the rules and an integration test file per domain in
   `crates/api/tests/` (shared harness in `tests/common/`, one test per file).

## Deliberate differences from Go

These are security fixes that keep the frontend working unchanged:

- **Client IP:** `X-Forwarded-For` and similar headers are ignored unless the
  peer is in `FERROPOST_TRUSTED_PROXIES`. In Go any client could send
  `X-Forwarded-For: 127.0.0.1` and pass the IP whitelist. The proxy also
  overwrites these headers before Go sees them.
- **Safe entrance:** a signed `ferropost_entrance` cookie bound to the current
  SafePath replaces Go's session flag. Changing SafePath invalidates old
  cookies, and existing users visit the safe path once after the switch.
  `/pmta/` (open/click tracking), ACME challenges and `/landing/video` are now
  exempt. Go answered 404 to them whenever a SafePath was set.
- **Tokens:** refresh tokens are no longer accepted as access tokens. If Redis
  is unreachable, the token-revocation check fails closed (Go skipped it).
- **Errors:** internal errors return a generic message and are logged. Go sent
  raw error text, including SQL errors, to the browser.
- **Paging:** `page_size` is capped at 1000.
- **Operation log:** snapshots contain the request payload only. Go's request
  structs captured the `Authorization` header, so access tokens ended up in
  `logs/core/operation_log/*.json`.
- **Error codes:** business errors carry a real code (400 rejected, 404 not
  found, 409 conflict) instead of Go's `code: 0`. The console only reads `msg`.
- **Tags:** creating a tag in a group that does not exist is rejected (Go
  created an orphan tag).
- **Template check:** `<br>`, `<img>` and other void elements no longer count
  as unclosed tags, so "HTML tags are not standard" only flags real problems.
  Go flagged almost every email.
- **Empty lists** are `[]` rather than `null`.
- **TLS:** renewed per-domain certificates are reloaded within 5 minutes
  without a restart. A missing default certificate falls back to an in-memory
  self-signed one.

## Roadmap

1. ~~Skeleton: config, DB, envelope, JWT/RBAC, edge, Go fallback, TLS~~ (done)
2. Simple domains: tags, operation_log, email_template (done), contact
3. `maillog_stat` and `overview`: streaming Postfix log parser, the `/pmta/` tracker, dashboard stats
4. Sending: `batch_mail`, `warmup` and the subscribe flow (it sends confirmation mail) on a durable Postgres job queue
5. System-facing: domains/DNS/DKIM, ACME, relay, multi-IP, mailboxes, mail_services, rspamd proxy
6. Switch off Go; move schema ownership to sqlx migrations
