# Ferropost core (`core-rs`)

Ferropost is an email marketing platform and mail server derived from
[BillionMail](https://github.com/aaPanel/BillionMail) and licensed, like it,
under AGPL-3.0. `core-rs` is the Rust core replacing the Go core (`../core`)
one domain at a time. Every route and job is ported; Go no longer runs.

The `ferropost` binary is the whole core: it terminates HTTP/HTTPS on the
console ports, serves the API, the console's files and Roundcube, and runs
the background jobs. The Vue frontend, the database schema and the API
contract are Go's. With `FERROPOST_GO_UPSTREAM` set, routes it does not know
still go to a Go core on a private address, which is how the migration ran.

```
browser ─► ferropost :80/:443 ─┬─► native route (Rust)  ─► Postgres / Redis
                               ├─► console files, Roundcube (PHP-FPM)
                               └─► anything else: 404, or a Go core if FERROPOST_GO_UPSTREAM is set
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

A job runs in Rust when its name is in `FERROPOST_RUST_JOBS` (comma-separated,
or `all`). During the migration Go read the same list and skipped those jobs
(`timers.OwnedByRust`), so a job never ran twice. The image sets `all`.

| Job | Replaces | Notes |
|---|---|---|
| `maillog` | `MallogEventHandler`, `AggregateMaillogsTask` | Follows `logs/postfix/mail.log` with a file cursor stored in the same transaction as the rows (exactly once; finishes `mail.log.1` after rotation; starts where Go's watermark stopped). Copies local deliveries every minute with a one-hour overlap. |
| `warmup` | `SenderIpWarmup().PeriodicTask`, `SenderIpMailProvider().PeriodicTaskForProviders` | Hourly (and at start-up): re-scores each sending IP in warmup and each of its eight provider groups from delivery, bounce, open, click and complaint data, then moves the warmup period and progress along. One aggregate query per score instead of Go's ID lists; a lock keeps a pass from running twice. Go's campaign sender keeps reading the same tables until sending moves. |
| `campaigns` | `ProcessEmailTasks`, `CleanupIdleExecutors`, `UpdateTaskJoinMailstat` | Sends campaigns from the `recipient_info` queue (claims with `SKIP LOCKED`, each submission recorded as it finishes, claims released after a restart), one worker per due campaign, one sender process at a time. Refreshes each campaign's delivery counts every minute. The `/api/batch_mail/task/*` and `/tracking/*` routes are native only while this job runs in Rust, since pausing and the speed act on the sender. |
| `api_mail` | `ProcessApiMailQueueWithLock` | Sends mail queued through the send API (`api_mail_logs`) continuously, woken as soon as the API queues mail (Go polled once a minute), with the same claim-and-settle queue as campaigns. |
| `mailboxes` | `NormalizeMailboxes`, `InitQuotaPluginAndUpdateUsedSpace`, `UpdateMailboxesUsedSpace`, `CheckMailboxesQuotaAlerts` | At start-up lower-cases addresses and, once per install, enables Dovecot's maildir quota. Hourly: reads every `maildirsize` into `used_quota` and the domain totals, and mails 90%/95% quota alerts (once a day per level, across restarts). |
| `relay` | `CheckRelayFirstSync`, `EnsurePostfixConfExists`, `UpdateRelayStatus` | At start-up runs Go's one-off `main.cf` migration (same marker file) and writes the relays to Postfix. Every 5 minutes tests each active relay's connection and login; the console shows the result (Go's check read a table that no longer exists). |
| `mail_services` | `FixPostfixMainConfig` | Five seconds after start-up checks `main.cf` (server name, header checks that hide authenticated senders' IPs, a real `myhostname`) and reloads Postfix only if it changed. |
| `ssl` | `AutoRenewSSL`, `FixDovecotSSLConfig` | Every 12 hours renews certificates this server obtained with a third of their lifetime left (uploaded ones in their last week), obtains missing mail host certificates (a failed host is retried after a day), and at start-up moves Dovecot's per-host SSL blocks after the global settings. |
| `multi_ip` | `ReapplyAllIptablesRules` | Three seconds after start-up replaces the host's SNAT rules (dedicated network → sending IP) in one privileged helper run, removing stale ones even when no dedicated IP is left. |
| `blacklist` | `CheckDomainsBlacklist` | Once a day (first pass ten minutes after start-up, then 24 hours after the last one, across restarts) checks every mail host's address on the DNS blocklists, three hours apart for up to eight domains as Go did, and mails the alert recipients about a listing. Honours the automatic-scan switch. |
| `domains` | `FreshRecords`, `RepairDKIMSigningConfig`, `FixRspamdDKIMSigningConfig` | At start-up makes missing DKIM keys, rewrites rspamd's `dkim_signing.conf` only if it changed (Go rewrote it and restarted rspamd at every start) and makes existing private keys readable by rspamd only. Every 5 minutes checks every domain's DNS records (cached for the domain list) and makes keys that went missing. `UpdateBaseURL` was not moved: it only filled Go's own memory. |
| `askai` | `AutoGetProjectInfo` | Reads the brand site of every AskAI project not read yet, every 10 minutes (a new project is read at once; Go polled every 5 seconds and retried a failing site forever). |
| `log_maintenance` | `CompressAndCleanupLogs`, the fail2ban access-log watcher | Ten minutes after start-up and then daily, gzips the core's logs from before today, keeps the newest thirty of each kind and packs operation-log days older than a month into `.tar.gz` (Go waited a day first). fail2ban is told about each new day's access log as `ferropost` creates it, whichever process owns this job. |
| `abnormal_recipient` | `AbnormalRecipientAutoStat` | Every 30 minutes counts one more failure for each address that bounced since the last pass (latest reason kept, one statement); campaigns skip an address at 3. |

## Ported so far

| Route | Notes |
|---|---|
| `/api/contact/group/*` (all 12 routes) | Create, import, export, update, delete, list, all, info, merge and counts. Create-and-import is one transaction; imports are one statement each and skip or overwrite duplicates; list counts subscribers in one query; export adds Excel; `info` fills unset subscription settings with the built-in defaults, as Go did. |
| `/api/contact/*` (all 9 routes) | Edits and moves keep the rows (tags, history) of groups an address stays in; deletes remove tag assignments; bulk tagging is one statement; the trend no longer skips months. |
| `/api/email_template/*` (all 8 routes) | Unique names decided by the constraint; `copy` picks the next free `_bak` name; deleting a missing template is a 404 (Go crashed); the content check ignores void elements such as `<br>`. |
| `/api/batch_mail/task/*` (12 routes), `/api/batch_mail/tracking/*` (2) | Campaigns: create, update, delete, list, find, pause, resume, speed, test mail, send counts, stats, delivery logs. Need the `campaigns` job (above). |
| `/api/login`, `/api/aapanel/sso`, `/api/logout`, `/api/refresh-token`, `/api/get_validate_code` | Signing in and out (Go's account, role and permission routes were never wired up). Tokens keep Go's format, plus a session ID so logout ends the whole session. |
| `/api/abnormal_recipient/*` (all 8 routes) | Blocklist of failing addresses: list, add, delete, clear, the automatic-scan switch, and the background group scan (MX check) with its log. |
| `/api/languages/get` (public), `/api/languages/set` | The console language. `set` needs a login (no permission, as in Go). |
| `/subscription/form` (public page) | Hosted form to subscribe to the listed groups. |
| `/api/mailbox/*` (all 9 routes) | Create, batch create, update, delete, list, all, export, import. Keeps the maildir and its quota file in step with the database and asks Dovecot to recount usage. |
| `/api/batch_mail/api/*` (all 7 routes) | Send-API keys (list, create, update, delete, stats) and queueing mail with one (`send`, `batch_send`: public, `x-api-key` header, Go's error codes 1001–1005). |
| `/api/unsubscribe/one_click` (public, new) | RFC 8058 target of the `List-Unsubscribe` header campaign mail now carries: a POST unsubscribes from the campaign's group, a GET shows the usual page. |
| `/api/unsubscribe`, `/api/unsubscribe/user_group`, `/api/unsubscribe_new` (public) | Accept Go's links in people's inboxes, with extra checks. Listing an address's groups needs that address's unsubscribe link. The one-click route sends the group's "you're unsubscribed" mail with a resubscribe link. |
| `/api/subscribe/submit`, `/api/subscribe/confirm` (public) | Forms post as before (form or JSON, values in the query or body). Addresses are validated, attributes are merged, double opt-in always goes through confirmation, and one confirmation mail per address and group goes out per 10 minutes. Mail is sent as `noreply@<default domain>`, creating that mailbox on first use as Go did. |
| `/pmta/<token>` (open pixel, click redirect) | Accepts Go's existing links. Counts an event and redirects only for mail this server sent, and only to `http`/`https`; stores the clicked URL; activity updates are immediate. |
| `/api/overview`, `/api/overview/failed` | Three queries instead of one per tile and chart; buckets generated in the server time zone (`TZ`) with calendar months; campaign filter counts each message once. |
| `/api/operation_log/*` (all 4 routes) | Usernames by join. Output logs are read backwards from the end, so a page costs only the lines returned and long lines no longer drop a whole file. |
| `/api/relay/*` (all 6 routes) | SMTP relays: list, add, edit, delete, unbound domains, connection test. Writes `master.cf`, `main.cf`, `sasl_passwd` and the pgsql maps, reloading Postfix only when they change, and rspamd's DKIM signing (relayed domains are signed by the provider). |
| `/api/services/*`, `/api/mail_bcc/*`, `/api/mail_forward/*`, `/api/postfix_queue/*` (all 19 routes) | Mail services: the editor for Postfix's, Dovecot's and rspamd's main configuration file (checked by the service before it stays), BCC rules and their Postfix maps, mail forwarding (`alias`), the deferred queue and Postfix's queue settings. |
| `/api/ssl/apply_cert`, `/api/ssl/console_apply_cert`, `/api/ssl/get_cert_list`, `/api/domains/set_ssl`, `/api/domains/get_ssl`, `/.well-known/acme-challenge/*` | Mail host and console certificates: Let's Encrypt over HTTP-01 (challenges answered here), uploads, and installation in Postfix's and Dovecot's SNI. |
| `/api/multi_ip_domain/apply`, `/api/multi_ip_domain/test` | Dedicated sending IPs: writes `docker-compose_addnetwork.yml` on the host and Postfix's transports (undone on failure), and checks a domain's address and SPF records for its IP. |
| `/api/domains/*` (all 8 routes) | Sending domains: create, update, brand flag, delete, list, all, refresh DNS records, default domain. A new domain gets Go's five system mailboxes, its DKIM keys and its mail host certificate, as before. |
| `/api/domain_blocklist/check`, `/api/domain_blocklist/logs` | Checks a mail host on 139 DNS blocklists in the background and serves the check's log. |
| `/api/askai/supplier/*` (all 15 routes) | AI providers and their models, in Go's files under `conf/supplier/` (built-in providers copied from the templates). |
| `/api/askai/project/*` (all 23 routes), `/media/*` (public) | AskAI brand projects in Go's files under `conf/askai/`: details, company profile, style, sitemap, footer, prompt, knowledge base and images. Images are stored and served here. |
| `/api/askai/chat/*` (all 9 routes) | AskAI chats designing email templates, streamed as server-sent events, in Go's files under `conf/chat/`. Go's AskAI code is removed. |
| Console files, `/roundcube/*` | The built console (`public/dist`), the subscription pages (`public/html`) and `index.html` for the console's own routes; Roundcube through PHP-FPM's FastCGI socket. Go's API docs (`/swagger`, `/api.json`) went with Go. |
| `/rspamd/*` | rspamd's web interface, logged in with the controller password, for admins (a cookie bound to their login session). |
| `/api/settings/*` (all 16 routes) | System settings: the config page, `.env` keys, the IP whitelist, the console certificate, the reverse-proxy URL, the API token, the API docs switch, blacklist switches and the alert mailbox. Applied at once; only the API docs switch restarts the core (Go reads it at start-up). |
| `/api/docker_api/*` (all 3 routes) | The platform's containers: list, usage (as `docker stats` computes it), restart. |
| `/api/file/download`, `/api/file/read` | Never implemented in Go; answered natively (501) so no file path reaches the proxy. |
| `/api/tags/*` (all 6 routes) | List: one query with a join instead of N+1 group lookups, literal keyword match. Writes: the unique constraint decides duplicates; bulk tagging is one all-or-nothing statement and matches addresses case-insensitively. |

Nothing else is served: an unknown `/api/` route gets the 404 envelope.

## Configuration

Shared settings come from the BillionMail `.env` (`DBPASS`, `REDISPASS`,
`REDISDB`, `HTTP_PORT`, `HTTPS_PORT`, `SafePath`, `IP_WHITELIST_ENABLE`,
`WEB_BASE_PATH`). Changes to `.env` take effect within about 2 seconds,
without a restart. Settings specific to Rust use `FERROPOST_*` process variables:

| Variable | Default | Purpose |
|---|---|---|
| `FERROPOST_ROOT` | current dir | Core directory (`languages/`, `public/`, `logs/`) |
| `FERROPOST_ENV_FILE` | `$FERROPOST_ROOT/../.env` | Shared env file |
| `FERROPOST_GO_UPSTREAM` | `http://127.0.0.1:8181` | Go core in internal mode; `none` once Go is gone |
| `FERROPOST_DATABASE_URL` | unix socket `../postgresql-socket` | Override for development |
| `FERROPOST_REDIS_URL` | `redis:6379` (container) / `127.0.0.1:26379` | Override for development |
| `FERROPOST_HTTP_PORT` / `FERROPOST_HTTPS_PORT` | `.env` values, then 80/443 | Listener ports |
| `FERROPOST_SSL_DIR` | `/etc/ssl/mail` | Default and per-domain certificates |
| `FERROPOST_TRUSTED_PROXIES` | none | CIDRs allowed to set `X-Forwarded-For` (e.g. a reverse proxy in front) |
| `FERROPOST_SERVER_IP` | looked up online | Public IP always allowed by the whitelist |
| `FERROPOST_JWT_SECRET` | `DBPASS`+`REDISPASS` | Must match Go's `jwt.secret` if that is set |
| `FERROPOST_ACCESS_LOG_DIR` | `$FERROPOST_ROOT/logs` | fail2ban access log directory |
| `FERROPOST_RUST_JOBS` | none | Background jobs owned by Rust (see below), or `all`; read by Go too |
| `TZ` | `UTC` | Time zone of dashboard chart buckets |
| `FERROPOST_POSTFIX_CONTAINER` | `postfix-billionmail` | Container queried for the deferred queue (`none` disables) |
| `FERROPOST_DOVECOT_CONTAINER` | `dovecot-billionmail` | Container where `doveadm` runs (`none` disables) |
| `FERROPOST_ACME_DIRECTORY` | Let's Encrypt | ACME directory certificates come from (e.g. its staging directory) |
| `FERROPOST_RSPAMD_URL` | `http://rspamd:11334` (container) / `http://127.0.0.1:21334` | rspamd's controller, behind `/rspamd/` |
| `FERROPOST_RSPAMD_CONTAINER` | `rspamd-billionmail` | Restarted when DKIM keys or signing change (`none` disables) |
| `FERROPOST_CORE_CONTAINER` | `core-billionmail` | This container, restarted for the API docs switch (`none` disables) |
| `FERROPOST_FETCH_PRIVATE` | off | Lets AskAI fetch private addresses (development and tests only) |
| `FERROPOST_PHP_FPM_SOCKET` | `$FERROPOST_ROOT/../php-sock/php-fpm.sock` | PHP-FPM serving Roundcube |
| `FERROPOST_WEBMAIL_ROOT` / `FERROPOST_WEBMAIL_SCRIPT_ROOT` | `$FERROPOST_ROOT/../webmail-data` / `/var/www/html` | Roundcube's files here and as PHP-FPM sees them |
| `FERROPOST_DOCKER` | on | `none` keeps every call away from the Docker socket (tests, development) |
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
the machine. The tests build the schema from the store's migrations, the
same ones the server applies.

## Database schema

`crates/store/migrations/` holds the schema; `ferropost` applies it at
start-up (`ferropost_store::migrate`). The first migration is the schema
Go created at every start (`core/internal/service/database_initialization`),
written to apply to a new database and to one Go already made, including
Go's move of pre-`bm_relay_config` relays. Later changes go in new files:
an applied migration must never change.

## Build and deploy

The core image is built on the server from the checkout:
`docker compose build core-billionmail`, which `install.sh` runs before the
first start and `update.sh` after merging new code. `Dockerfiles/core/Dockerfile`
has three stages:

- **console:** `pnpm install --frozen-lockfile` and `pnpm build` (Node 26,
  pnpm 12.20.0). Dependencies' install scripts stay off; the list is in
  `core/frontend/pnpm-workspace.yaml`, as pnpm stops an install on scripts
  nobody decided on.
- **core:** a static musl `ferropost` (`cargo build --release --locked`). The
  dependencies are compiled first against empty crates, in their own layer,
  so a code change recompiles only the workspace.
- **runtime:** Alpine with supervisord running `ferropost` alone, with
  `FERROPOST_GO_UPSTREAM=none` (no Go fallback) and `FERROPOST_RUST_JOBS=all`
  (every background job).

The build context is the repository root, which on a server also holds the
mail, the databases, the keys and `.env`; `.dockerignore` is an allowlist of
the files the image copies. Compose names the image `ferropost/core:local`
with `pull_policy: never`: it builds the image when it is missing and never
pulls it, so no registry image can stand in for the local code.
`update.sh` builds the new image while the old containers keep running (a
failed build stops nothing), then restarts. The image it replaced stays as
`ferropost/core:previous` (the one before that is removed), so going back is:

```bash
docker tag ferropost/core:previous ferropost/core:local && docker compose up -d
```

An older core starts on a database a newer one migrated (`migrate` leaves
migrations it does not know alone). That is safe while migrations only add
tables and columns; a migration that changes or removes one breaks going
back, and its release notes must say so.

The Dockerfile uses only classic instructions (no cache mounts): without the
buildx plugin, as after `install.sh`'s fallback to Docker's static binaries,
Compose builds with Docker's classic builder.

**The Go core** is not built any more. Commit `6bdea793` (before step 6d) is
the last tree in which it ran behind `ferropost`; its image needed the Go and
`ferropost` binaries built beforehand (`core/go-build.sh`, and that commit's
`core-rs/build.sh`) and the old console build in `core/public/dist`. The Go
source stays in `core/` until it is removed for good.

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
  Tokens of disabled or deleted accounts stop working within 20 seconds (Go
  honoured them until expiry, and let disabled accounts sign in). Logout
  ends the access and refresh token together, and a refresh token works
  once (Go left both usable for seven days).
- **Sign-in:** failed logins and captchas are counted in Redis per real
  client IP (Go kept them in memory, keyed on an `X-Forwarded-For` anyone
  could set, so the lock was easy to dodge); an unknown username takes as
  long to reject as a wrong password; the captcha is an SVG with stroked,
  individually transformed glyphs (Go: PNG) and each one works once; the
  audit log no longer stores the issued tokens.
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
  base64): the core submits as each sender with them, and the console shows
  them. Removing that needs Dovecot master-user submission and dropping the
  console's password column.
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
- **Mailboxes:** new and changed passwords are hashed with SHA512-CRYPT (with
  Dovecot's `{SHA512-CRYPT}` prefix; Go and Roundcube write MD5-CRYPT, which
  keeps working). An imported mailbox without a password gets a random one:
  Go gave every such mailbox `123456`, open to anyone over IMAP and SMTP.
  Imports default to the normal quota (Go: 1000 bytes). `mailbox/all` no
  longer returns hashes, the list leaves out the reversible copy, and the
  audit log never records passwords (Go logged the reversible copy).
  `update` keeps fields it is not sent, the domain must exist, local parts
  are validated (Go's pattern was unanchored), batch passwords come from a
  secure generator (Go seeded `math/rand` with the time) and only mailboxes
  actually created are reported. Quota alerts for a domain go to its
  administrator mailboxes (Go mailed `noreply@` from itself).
- **Abnormal recipients:** a manual block always blocks (Go left an address
  already seen once below the blocking count). The group scan accepts
  domains with only an address record (RFC 5321 implicit MX), treats a null
  MX as unreachable, and never acts on a domain whose lookup failed: Go
  treated a DNS timeout as "no MX", so a hiccup could block or delete a
  whole domain's contacts. Bounce reasons longer than the column no longer
  fail the whole batch.
- **Language:** changing the console language needs a login; Go let anyone
  change it for everybody.
- **`/subscription/form`:** subscribing follows each group's rules (double
  opt-in, confirmation and welcome mails, the rate limit) where Go made the
  address active everywhere and mailed "subscription confirmed" with the
  visitor's name pasted into the HTML. Group names and the address are
  escaped on the pages, and the form token is signed with an expiry instead
  of a server session. The page still lists every group, as in Go.
- **Settings:** `get_system_config` no longer sends the admin password, the
  console's TLS private key or the alert mailbox password, and sends the API
  token to admins only. `.env` values are checked against a shell-safe
  allow-list: `bm.sh` sources `.env` as root, and Go's blocklist let spaces
  and quotes through, so a password like `x touch /tmp/p` ran a command.
  Keys that only apply when `bm.sh` recreates the containers (ports, time
  zone, Docker network, fail2ban, database and Redis credentials) are
  refused; Go wrote them and restarted the core, which applied nothing and,
  for the HTTP ports, left the console listening on a port Docker does not
  publish. A new admin login is applied to the account at once, by admins
  only, and never written to the audit log in clear. The IP whitelist takes
  CIDR ranges, refuses changes that would lock out the caller, and switches
  off when emptied. A certificate is saved only with its own key, files are
  replaced atomically and the key is never logged (Go logged it); the server
  picks it up within a minute instead of restarting, and Postfix and Dovecot
  are reloaded with it. Deleting it puts a self-signed certificate in its
  place, so Postfix and Dovecot keep a default certificate. The alert mailbox logs
  in over verified TLS, its password is kept when the console sends it back
  empty (for the same server only) and its file is private.
- **API token:** only the token issued last works, on every route; Go never
  checked, so regenerating it left every
  earlier token working forever. Regenerating is reserved to admins.
- **Docker API:** only the platform's containers are listed, inspected or
  restarted; Go restarted or read any container on the host. CPU usage is
  correct on cgroup v2 hosts (Go showed 0%) and memory excludes the page
  cache, as `docker stats` does.
- **SMTP relays:** the list no longer sends relay passwords (Go sent them
  decrypted); an edit without a password keeps the stored one, and a
  connection test without one uses the stored password of the relay with
  the same server, port and user only. Edits change only the fields they
  send: Go wiped a relay's login whenever `auth_user` was missing (the
  console's on/off switch sends only `id` and `active`) and disabled it
  whenever `active` was missing. Host, HELO name and login are checked
  before they reach Postfix's files (a line break in Go's HELO name added
  options to `master.cf`), and sender domains must be the server's own.
  `sasl_passwd` is readable by root only (Go: by everyone); port 25 relays
  use TLS when offered (Go turned it off, sending the password in clear);
  two relays with one name get distinct Postfix services. Postfix is
  reloaded and rspamd restarted only when their files change. The relay
  maps stay in `main.cf` while dedicated-IP transports use them. The
  connection test reports the server name, TLS and login methods; the list
  shows each relay's real status (Go always said "Connected") and checks
  SPF against the relay's configured SPF IP or include.
- **Configuration editor:** a saved `main.cf`, `dovecot.conf` or
  `rspamd.conf` is checked by the service (`postfix check`, `doveconf -n`,
  `rspamadm configtest`) and the previous file is put back when it fails,
  so a typo no longer stops mail at the next restart; ten backups are kept
  instead of one more per save, forever.
- **BCC and forwarding:** addresses are checked before they reach Postfix's
  maps (a space or line break in Go's added rules); an address keeps one
  active BCC rule per type, since Postfix copies to one address per key;
  forward targets are checked and may be separated by lines or commas.
  Edits change only what they send (Go switched a forward off when
  `active` was missing). The lists read the console's `page` and `keyword`
  (Go expected `page_num` and `search_key`, so BCC paging and both searches
  did nothing), and the BCC search narrows the other filters (Go's replaced
  them).
- **Postfix queue:** the domain filter is applied here; Go ran it through
  `sh -c "postqueue -j | grep -i '<domain>'"`, so the request could run any
  command as root in the Postfix container. Queue IDs are checked (`ALL`
  passed to Go's `postsuper -d` emptied the queue), failures are reported
  (Go ignored `postsuper`'s exit status), and one `docker exec` handles a
  batch of IDs. Queue settings must be Postfix time values (Go wrote any
  text into `main.cf`) and replace every definition of the setting (Go
  changed the first, which Postfix ignores when a later one exists).
  `main.cf` gets a mail host name for `myhostname` (Go used the bare first
  domain); an existing value is kept.
- **Certificates:** Postfix's SNI table is built with `postmap -F`, which a
  `hash:` SNI table needs (Go's plain `postmap` stored file names, so
  Postfix always presented its default certificate). Postfix and Dovecot
  are reloaded instead of restarted, and the core is not restarted at all
  (Go restarted all three for every certificate); a new console certificate
  also reaches Postfix and Dovecot, which use it as their default. A key is
  only installed with its own certificate, private keys are owner-only (Go
  wrote them 0755), `get_ssl` and the audit log never contain one, and the
  new certificate and key are not also dropped in the shared `ssl/`
  directory. Certificates are renewed with a third of their lifetime left
  (Go: 3 days), a failed host is retried after a day (Go never retried it),
  and a host without an address record fails before Let's Encrypt is
  asked. Keys are RSA 2048, as Go's were. Not yet run against Let's Encrypt
  itself: the order flow is `instant-acme`'s.
- **Dedicated IPs:** host commands run as argument lists in one helper
  container started from the core's own image; Go pulled `alpine:latest`
  and pasted database values into a `sh -c` string, one privileged
  container per rule. Old SNAT rules are deleted by specification (Go used
  line numbers, which move when Docker edits the chain) and are removed
  once no dedicated IP is left. Postfix joins the main network at
  `<IPV4_NETWORK>.100` (Go hard-coded `172.66.1.100`, breaking a custom
  network), the rewritten compose file keeps its blank lines, a removed
  dedicated IP's transport is really deleted (Go looked for `domain`, but
  `bm.sh` stores `@domain`), and applying with none left removes the old
  transports from `master.cf`.
- **AI providers:** provider names are checked before they become folder
  names (Go's `../..` reached any folder, and removing a provider deleted
  it); the files holding API keys are owner-only (Go: 0777) and keys are
  masked in every answer, the mask sent back keeping the stored key.
  Removing a model reports success (Go answered "Model not found" when it
  worked); edits made while a provider is off no longer save all its
  models as off; adding a model to an unknown provider fails.
- **AskAI brand projects** no longer use BillionMail's own service
  (`cdn.billionmail.com`). Go sent each brand URL there to be read and
  every uploaded image there to be hosted; here the site is fetched from
  this server (public addresses only, never the containers' networks,
  with size and time limits), its details are read from the HTML and the
  configured AI model fills in the rest (industry, company name, brand
  colours), and images are kept in `data/media/` and served at
  `/media/<id>.<ext>` (PNG, JPEG, GIF, WebP and ICO only: no SVG). A site
  that cannot be read is tried three times and the project is then marked
  read, so the console stops waiting (Go retried every five seconds,
  forever). A setting sent empty is cleared and one left out is kept: Go
  could not clear anything, and saving the fonts alone wiped the brand
  colours. Reading a setting no longer writes its default file; ids and
  domains are checked before they become file names (Go's `../` reached
  any `.json` file). An uploaded logo becomes the project's logo (the
  console now shows it).
- **AskAI chats:** the `http_request` tool fetches pages from this server
  (public addresses only) instead of BillionMail's own service, and a
  model may call it five times per answer (Go had no limit, so a model
  could loop). A chat answers one question at a time (Go interleaved two
  answers into the same files); token counts are the provider's own when
  it reports them (Go counted streamed chunks); chat ids are checked
  before they become folder names (Go's `../` reached, and removing a chat
  deleted, any folder); a provider error is shown in the chat, and a
  failed answer is not kept in the history.
- **Console files:** built assets under `/static/` (their names carry a
  content hash) are cached for a year; everything else is revalidated
  with an ETag. Unknown `/api/` routes answer with an envelope.
- **Roundcube:** its private folders (`config`, `temp`, `logs`, `bin`,
  `SQL`, `installer`), hidden files and README/composer files are refused,
  as its own web server guide does; Go served them, Roundcube's logs
  included. PHP sees the visitor's address (Go passed its own, so
  Roundcube's per-address protections saw one client) and this server's
  port (Go passed the visitor's); a `Proxy` request header is dropped
  (httpoxy); responses stream instead of being buffered whole.
- **Start-up:** `ferropost` applies the schema migrations, syncs the
  administrator's login from `ADMIN_USERNAME`/`ADMIN_PASSWORD` (what
  `bm.sh change-password` relies on; the password is hashed again only
  when it changed, where Go rewrote it at every start), issues the first
  API token, writes rspamd's controller password and makes a self-signed
  console certificate when there is none (its key owner-only; Go: 0777).
  It logs to `logs/core/out/<date>.log` as well as standard output, so the
  console's output log page keeps working without Go.
- **No reporting to aaPanel:** Go posted the number of mails sent and
  relays added to `aapanel.com` every two hours (`collect`). That code is
  removed.
- **Video outreach is gone** (`/api/video_outreach/*`, `/landing/video`
  and its job, in Go and in the console). It needed ffmpeg, Node
  Playwright and Anthropic, Cartesia, SyncLabs and Cloudflare R2 keys that
  no install provides. Templates using `.VideoOutreach.*` still render
  from contact attributes.
- **Domains:** the list no longer sends every domain's TLS private key,
  and `all` marks the default domain (Go never did, so the campaign form
  could not preselect it). An update changes only what it is given: Go
  set `active` to 1 and the brand flag to 0 unless sent (the console sends
  neither, so every edit cleared the flag), removed the dedicated address
  when the field was absent (the console's form never filled it in; the
  form now does), and could not turn the catch-all address off. A
  dedicated address is checked before the domain is created, so a failed
  check no longer leaves a half-made domain. Deleting a domain also
  removes its BCC rules, dedicated address and default-domain setting and
  stops rspamd signing for it (Go left all of these); mail on disk and the
  DKIM keys stay, so the published records still match if it comes back.
  Unknown domains are refused instead of "updated" or "deleted".
- **DNS records:** checked by meaning, not as text. SPF is evaluated
  (RFC 7208) for the address mail leaves from: Go wanted the expected
  `ip4:` term spelled out, so a policy covering the server through `mx`,
  `a` or an include looked wrong, `ip4:1.2.3.45` passed for `1.2.3.4`, and
  two SPF records (which break SPF) passed. DKIM keys are compared tag by
  tag (Go wanted the exact text, so other spacing or an extra tag looked
  missing). DMARC needs one record with a policy (Go tested its own
  expected value, so any `v=DMARC1` record passed, even two of them). Host
  names compare without case. A dedicated sending address is part of the
  SPF and PTR records (Go asked for the shared address's PTR). Listing
  domains never makes keys or restarts rspamd; Go made missing keys there
  and restarted rspamd once per key.
- **DKIM keys:** made here instead of by `rspamadm` in the rspamd
  container; an existing private key is never replaced (a missing public
  half is derived from it, where Go made a new pair and the published
  record stopped matching); private keys belong to rspamd's user, mode
  0600 (Go: 0644).
- **Blocklist checks:** lists are queried 16 at a time through the
  system resolver, and "no record" is a definite answer; Go asked Google's
  resolver one list after another, retrying and sleeping on every clean
  list. Spamhaus refuses public resolvers with `127.255.255.x`, which Go
  counted as passed, so a Spamhaus listing never showed: it counts as
  invalid now (run the core with a local resolver to get answers). The
  duplicate lists and the domain lists (SURBL, URIBL, which never list an
  address) are gone. The log route serves check logs only; Go returned any
  file named in the request, `.env` included. The daily scan remembers its
  last run, so restarts neither skip nor repeat it.
- **rspamd interface:** Go accepted any token it had kept in its server
  session, which only held one after the browser's last call to a route Go
  served (so the interface stopped working as routes moved here) and kept
  it after logout. Access now needs an admin's signed cookie, bound to the
  login session: logging out, losing the admin role or a disabled account
  ends it at once. The console's cookies and token are not passed to
  rspamd.
- **TLS:** renewed per-domain certificates are reloaded within 5 minutes
  without a restart. A missing default certificate falls back to an in-memory
  self-signed one.

## Roadmap

1. ~~Skeleton: config, DB, envelope, JWT/RBAC, edge, Go fallback, TLS~~ (done)
2. ~~Simple domains: tags, operation_log, email_template, contacts~~ (done)
3. ~~`maillog_stat` and `overview`: Postfix log ingestion, the `/pmta/` tracker, dashboard stats~~ (done)
4. ~~Sending: building blocks, subscribe/unsubscribe flows, IP warmup job, campaigns on a durable Postgres queue, the send API~~ (done)
5. System-facing: mailboxes (done); abnormal recipients, the subscription form and languages (done); sign-in (done); settings, files and the Docker API (done); relay (done); mail_services and the rspamd proxy (done); certificates and ACME (done); dedicated IPs (done); blocklist checks (done); domains, DNS records and DKIM keys (done); video outreach (dropped); AskAI, self-hosted (done)
6. Switch off Go: schema in sqlx migrations (done); start-up work, the remaining jobs and log files (done); static files and Roundcube (done); the image without Go (done); the image built from source on the server (done). Left: removing the Go source. Go's generated API docs (`/swagger`) already went when Go stopped running
