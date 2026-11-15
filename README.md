# Ferropost

Open-source mail server and email marketing platform. Run newsletters,
campaigns and transactional mail from your own server, with your own domains
and your own data.

> **Status: early development.** Ferropost is moving its backend from Go to
> Rust one area at a time, and there is no release yet. The bundled
> `docker-compose.yml` still pulls the upstream BillionMail images, which do
> not contain the Ferropost core.

## Features

- **Mail server:** Postfix, Dovecot and Rspamd, plus Roundcube webmail
- **Sending domains:** DNS record checks, DKIM signing, free TLS certificates
- **Audience:** contacts, groups, tags, and subscribe and unsubscribe forms
- **Campaigns:** templates, scheduled sends, and an API for transactional mail
- **Deliverability:** sender IP warmup, and open, click and bounce tracking

## How it is built

| Path | What it is |
|---|---|
| [`core-rs/`](core-rs/README.md) | The new Rust core (axum, sqlx). It serves the console on ports 80/443 and answers the routes already ported. |
| `core/` | The original Go core (GoFrame), being retired. It answers every route not yet ported, behind the Rust core. |
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

`core-rs/build.sh` builds the static Linux binaries that go into the core image.

## License

Ferropost is licensed under the [GNU AGPL v3.0](LICENSE). It is derived from
[BillionMail](https://github.com/aaPanel/BillionMail) by aaPanel, which is
licensed under the same terms.

To report a security issue, see [SECURITY.md](SECURITY.md).
