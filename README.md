# Ferropost

Open-source mail server and email marketing platform. Run newsletters,
campaigns and transactional mail from your own server, with your own domains
and your own data.

> **Status: early development.** Ferropost's backend now runs in Rust
> alone, and there is no release yet. `install.sh` and `update.sh` build the
> core image on your server from this repository's source (the build needs
> about 2.5 GB of free memory, or swap); the mail service images (Postfix,
> Dovecot, Rspamd) are still pulled from upstream BillionMail.

## Features

- **Mail server:** Postfix, Dovecot and Rspamd, plus Roundcube webmail
- **Sending domains:** DNS record checks, DKIM signing, free TLS certificates
- **Audience:** contacts, groups, tags, and subscribe and unsubscribe forms
- **Campaigns:** templates, scheduled sends, and an API for transactional mail
- **Deliverability:** sender IP warmup, and open, click and bounce tracking

## How it is built

| Path | What it is |
|---|---|
| [`core-rs/`](core-rs/README.md) | The Rust core (axum, sqlx). It serves the console and the API on ports 80/443 and runs the background jobs. |
| `core/` | The original Go core (GoFrame), retired: it no longer runs, and its source stays until it is removed. |
| `core/frontend/` | The web console (Vue 3, TypeScript, Naive UI) |
| `conf/`, `Dockerfiles/` | Configuration and images for the mail services |

The design, settings and porting roadmap are in
[`core-rs/README.md`](core-rs/README.md).

## Development

```bash
# Rust core
cd core-rs && cargo fmt --check && cargo clippy --all-targets && cargo test

# Go core
cd core && go vet ./... && go build -o billionmail main.go

# Web console
cd core/frontend && pnpm install && pnpm dev    # pnpm test, pnpm run lint
```

`docker compose build core-billionmail` builds the core image (the console and
the Rust core, from source) with `Dockerfiles/core/Dockerfile`.

## License

Ferropost is licensed under the [GNU AGPL v3.0](LICENSE). It is derived from
[BillionMail](https://github.com/aaPanel/BillionMail) by aaPanel, which is
licensed under the same terms.

To report a security issue, see [SECURITY.md](SECURITY.md).
