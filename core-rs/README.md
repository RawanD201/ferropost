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
| `crates/api` | axum app: edge, JWT auth, RBAC, response envelope, Go proxy, native routes; the campaign sender (`src/campaigns`), which needs the app state. |
| `crates/jobs` | Background jobs moved out of Go (mail-log ingestion, aggregation). |
| `crates/sender` | Mail composition: Go-compatible templates, spintax, signed tracking links, unsubscribe tokens, SMTP to Postfix. |
| `crates/server` | `ferropost` binary: listeners, TLS/SNI certificates, graceful shutdown. |

## Background jobs

A job moves to Rust by name in `FERROPOST_RUST_JOBS` (comma-separated).
Both processes read it: Go skips the listed jobs (`timers.OwnedByRust`) and
Rust runs exactly those, so a job never runs twice. Unset means Go keeps
everything. supervisord sets it for both programs.

| Job | Replaces | Notes |
|---|---|---|
| `maillog` | `MallogEventHandler`, `AggregateMaillogsTask` | Follows `logs/postfix/mail.log` with a file cursor stored in the same transaction as the rows (exactly once; finishes `mail.log.1` after rotation; starts where Go's watermark stopped). Copies local deliveries every minute with a one-hour overlap. |
| `warmup` | `SenderIpWarmup().PeriodicTask`, `SenderIpMailProvider().PeriodicTaskForProviders` | Hourly (and at start-up): re-scores each sending IP in warmup and each of its eight provider groups from delivery, bounce, open, click and complaint data, then moves the warmup period and progress along. One aggregate query per score instead of Go's ID lists; a lock keeps a pass from running twice. Go's campaign sender keeps reading the same tables until sending moves. |
| `campaigns` | `ProcessEmailTasks`, `CleanupIdleExecutors`, `UpdateTaskJoinMailstat` | Sends campaigns from the `recipient_info` queue (claims with `SKIP LOCKED`, each submission recorded as it finishes, claims released after a restart), one worker per due campaign, one sender process at a time. Refreshes each campaign's delivery counts every minute. The `/api/batch_mail/task/*` and `/tracking/*` routes are native only while this job runs in Rust, since pausing and the speed act on the sender. |
| `api_mail` | `ProcessApiMailQueueWithLock` | Sends mail queued through the send API (`api_mail_logs`) continuously, woken as soon as the API queues mail (Go polled once a minute), with the same claim-and-settle queue as campaigns. |

## Ported so far

| Route | Notes |
|---|---|
| `/api/contact/group/*` (all 12 routes) | Create, import, export, update, delete, list, all, info, merge and counts. Create-and-import is one transaction; imports are one statement each and skip or overwrite duplicates; list counts subscribers in one query; export adds Excel; `info` fills unset subscription settings with the built-in defaults, as Go did. |
| `/api/contact/*` (all 9 routes) | Edits and moves keep the rows (tags, history) of groups an address stays in; deletes remove tag assignments; bulk tagging is one statement; the trend no longer skips months. |
| `/api/email_template/*` (all 8 routes) | Unique names decided by the constraint; `copy` picks the next free `_bak` name; deleting a missing template is a 404 (Go crashed); the content check ignores void elements such as `<br>`. |
| `/api/batch_mail/task/*` (12 routes), `/api/batch_mail/tracking/*` (2) | Campaigns: create, update, delete, list, find, pause, resume, speed, test mail, send counts, stats, delivery logs. Need the `campaigns` job (above). |
| `/api/batch_mail/api/*` (all 7 routes) | Send-API keys (list, create, update, delete, stats) and queueing mail with one (`send`, `batch_send`: public, `x-api-key` header, Go's error codes 1001–1005). |
| `/api/unsubscribe/one_click` (public, new) | RFC 8058 target of the `List-Unsubscribe` header campaign mail now carries: a POST unsubscribes from the campaign's group, a GET shows the usual page. |
| `/api/unsubscribe`, `/api/unsubscribe/user_group`, `/api/unsubscribe_new` (public) | Accept Go's links in people's inboxes, with extra checks. Listing an address's groups needs that address's unsubscribe link. The one-click route sends the group's "you're unsubscribed" mail with a resubscribe link. |
| `/api/subscribe/submit`, `/api/subscribe/confirm` (public) | Forms post as before (form or JSON, values in the query or body). Addresses are validated, attributes are merged, double opt-in always goes through confirmation, and one confirmation mail per address and group goes out per 10 minutes. Mail is sent as `noreply@<default domain>`, creating that mailbox on first use as Go did. |
| `/pmta/<token>` (open pixel, click redirect) | Accepts Go's existing links. Counts an event and redirects only for mail this server sent, and only to `http`/`https`; stores the clicked URL; activity updates are immediate. |
| `/api/overview`, `/api/overview/failed` | Three queries instead of one per tile and chart; buckets generated in the server time zone (`TZ`) with calendar months; campaign filter counts each message once. |
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
| `FERROPOST_RUST_JOBS` | none | Background jobs owned by Rust (see below); read by Go too |
| `TZ` | `UTC` | Time zone of dashboard chart buckets |
| `FERROPOST_POSTFIX_CONTAINER` | `postfix-billionmail` | Container queried for the deferred queue (`none` disables) |
| `FERROPOST_MAILLOG_PATH` | `$FERROPOST_ROOT/../logs/postfix/mail.log` | Postfix log to ingest |
| `FERROPOST_SMTP_HOST` / `FERROPOST_SMTP_PORT` | `postfix` (container) / `localhost`, 25 | Where subscription mail is submitted |
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
FERROPOST_TEST_REDIS_URL=redis://:test@127.0.0.1:56379/1 cargo test --tests
```

Mail the tests trigger goes to an SMTP sink inside the test process (see
`crates/api/tests/common`), so no mail server is needed and nothing leaves
the machine.

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
- **Contact import:** every address is checked (Go skipped plain-text
  lines), `user+tag@` addresses are accepted, duplicates are skipped instead
  of failing the whole file, and a failed import leaves no empty group.
- **Group updates:** flags left out of the request keep their value (Go reset
  `double_optin` and `send_welcome_email` to 0); a missing group is a 404.
- **Merging groups** keeps each contact's confirmed status and newest
  attributes (Go dropped both, so merged contacts dropped out of tag sends).
- **Deleting a group** also removes its tags and their assignments.
- **Subscribe tokens** come from `gen_random_uuid()` instead of a time-seeded
  MD5.
- **Editing or moving contacts** keeps the rows of groups the address stays
  in. Go deleted every row of the address and recreated them, losing tags,
  activity and campaign history, and a move into a group where the address
  already existed failed outright. `edit` without groups now applies the
  change (Go did nothing but reported success), and omitted fields of
  `edit_ndp` keep their value (Go reset them to 0).
- **Deleting contacts** also removes their tag assignments.
- **Export** honours `include_unsubscribe: false` (Go always exported
  unsubscribed contacts), supports Excel (Go answered "not implemented") and
  sorts merged exports by address (Go's order was random).
- **Subscriber trend** walks calendar months, so a window starting on the
  29th–31st no longer drops February.
- **Mail-log ingestion** is exactly-once: Go re-read the last second on every
  pass and stored deferrals again, missed lines still in `mail.log.1` after
  rotation, and guessed the year of syslog timestamps from the file's
  modification time (wrong across New Year).
- **Templates** render with `gtmpl` (Go's template language) using Go's
  data model, helpers and fallback; output is checked byte for byte against
  GoFrame's `gview`. Spintax works in one pass (Go was quadratic) and leaves
  `<SCRIPT>` blocks alone regardless of case.
- **Outgoing mail** (subscription mail now, campaigns from step 4c): headers are encoded and cannot be
  injected, a plain-text part accompanies the HTML, and the session to
  Postfix upgrades to TLS. Mailbox passwords stay stored reversibly (hex of
  base64), as Go needs them to submit as each sender; replacing that needs a
  Postfix-side change and is tracked for step 5.
- **Unsubscribe links:** Go signed them with a secret derived from fixed
  default values, identical on default installs, so anyone could forge an
  unsubscribe for any address. New links use a random secret; Go's links
  (valid 30 days) are still accepted, but only for an address that received
  that campaign or is in that group.
- **Unsubscribe page:** listing the groups of an address now needs a valid
  unsubscribe link for it. Go answered for any address, so anyone could see
  which lists a person was on. `public/html/unsubscribe.html` sends the link
  along.
- **Subscribe form:** addresses are validated (Go stored any text), an empty
  form token is rejected, and submitted attributes are merged into existing
  ones instead of replacing them. On a double opt-in list, someone who left
  is re-added only after confirming again; Go put them straight back on the
  list, so anyone could re-subscribe any address. Confirmation mail is
  limited to one per address and group per 10 minutes (Go had no limit, so
  the public form could flood any inbox), and only an address that asked to
  subscribe can be confirmed.
- **Tracking links:** Go's link "encryption" carries its own key, so anyone
  can decode or forge a link, including a click link that redirects to any
  site from your mail domain (an open redirect usable for phishing). Old
  links still work, but a click only counts and redirects when its message
  ID was logged by this server, and only to `http`/`https` URLs. Signed
  links replace the format when sending moves to Rust (step 4).
- **Dashboard charts** use one time zone for labels and gap filling (Go
  mixed the database's and the server's), step months by calendar month (Go
  stepped 30 days, skipping or repeating months), and are always in order
  (two Go charts were unsorted). A campaign filter no longer counts a
  message twice when it has two recipient rows.
- **Local-delivery aggregation** re-scans an hour of overlap, so a delivery
  logged after its sender line is no longer skipped, and matches domains
  exactly instead of with `LIKE`.
- **IP warmup:** finishing a warmup (70,000 messages in the window) now
  sticks. Go set the period to 0 and the next step of the same hourly pass
  reset it to 21 or 45 days and pulled progress back below 100. Limits past
  the seven-day schedule saturate: after about 140 days Go's conversion
  overflowed to a negative daily limit, which stops sending, so every
  warmup campaign stalled for good.
- **Campaign sending:** the queue survives restarts (Go kept claims in
  memory, so a restart stranded them), and recipients held back by warmup
  limits are retried (Go left them claimed, so such campaigns never
  finished). Each message is rendered once; Go rendered the result again,
  executing template syntax found in subscribers' own attributes. Mail
  carries `List-Unsubscribe` and one-click `List-Unsubscribe-Post`, which
  Gmail and Yahoo require of bulk senders, and unsubscribe links are no
  longer click-tracked (Go counted unsubscribes as clicks). Warmup limits
  apply per provider group (Go regrouped the group name, so every
  recipient counted as "other"). The circuit breaker, a deleted template or
  a sender without a mailbox pause the campaign visibly; Go paused only in
  memory or failed every message. One SMTP connection pool per campaign
  replaces a session per message.
- **Campaign edits:** `update` changes only the fields it receives (Go reset
  `unsubscribe` to 0, ignored `warmup`, could not clear the tag filter and
  crashed without a subject) and rebuilds the recipient list when the tag
  filter changes before sending starts (Go kept the old list). `speed` works
  for any campaign. Test mail renders the template for any address (Go sent
  raw tags to non-contacts). The list's keyword no longer bypasses the
  status filter, and the deferred count is real (Go always stored 0).
- **Send API:** an API key may send only as mailboxes on its own domain
  (Go let a key send as any mailbox on the server), expired keys are
  refused and `reset_key` issues a new key (Go stored both settings and
  ignored them), addresses are validated, and people who unsubscribed from
  the API's group are not mailed. The queue cannot send twice: Go's lock
  never excluded a second run and a 15-second deadline could stop a run
  between sending and recording. Mail is rendered for every recipient (Go
  sent the raw template to addresses that were not contacts) and carries
  the one-click unsubscribe headers. The list's open and click rates are
  real (Go filtered them by an empty window, so they were always 0).
- **TLS:** renewed per-domain certificates are reloaded within 5 minutes
  without a restart. A missing default certificate falls back to an in-memory
  self-signed one.

## Roadmap

1. ~~Skeleton: config, DB, envelope, JWT/RBAC, edge, Go fallback, TLS~~ (done)
2. ~~Simple domains: tags, operation_log, email_template, contacts~~ (done)
3. ~~`maillog_stat` and `overview`: Postfix log ingestion, the `/pmta/` tracker, dashboard stats~~ (done)
4. ~~Sending: building blocks, subscribe/unsubscribe flows, IP warmup job, campaigns on a durable Postgres queue, the send API~~ (done)
5. System-facing: domains/DNS/DKIM, ACME, relay, multi-IP, mailboxes, mail_services, rspamd proxy
6. Switch off Go; move schema ownership to sqlx migrations
