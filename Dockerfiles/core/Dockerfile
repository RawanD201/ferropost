# The Ferropost core image, built from this repository's source:
#
#   docker compose build core-billionmail     (install.sh and update.sh run it)
#
# The build context is the repository root, and .dockerignore lets in only
# what is copied below: on a server that folder also holds the mail, the
# databases and the keys.
#
# Only classic instructions are used, so the image builds with BuildKit and
# with Docker's classic builder (Compose falls back to it without buildx).

ARG NODE_IMAGE=node:26-slim
ARG RUST_IMAGE=rust:1.99-alpine
ARG RUNTIME_IMAGE=alpine:3.24

# --- The web console ------------------------------------------------------------------------
FROM ${NODE_IMAGE} AS console
ARG PNPM_VERSION=12.20.0
# pnpm's install script only puts its native binary in place of the launcher
# (saving a Node.js start per call); the launcher runs that same binary.
RUN npm install --global --ignore-scripts pnpm@${PNPM_VERSION}
WORKDIR /src/core/frontend
# Dependencies first: this layer is reused until the lockfile changes.
COPY core/frontend/package.json core/frontend/pnpm-lock.yaml core/frontend/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY core/frontend/ ./
RUN pnpm build

# --- The Rust core --------------------------------------------------------------------------
FROM ${RUST_IMAGE} AS core
RUN apk add --no-cache musl-dev
WORKDIR /src/core-rs
# Dependencies first, compiled against empty crates: this layer is reused
# until Cargo.lock or a manifest changes, so a code change compiles only
# Ferropost's own crates.
COPY core-rs/Cargo.toml core-rs/Cargo.lock ./
COPY core-rs/crates/api/Cargo.toml crates/api/
COPY core-rs/crates/common/Cargo.toml crates/common/
COPY core-rs/crates/domain/Cargo.toml crates/domain/
COPY core-rs/crates/jobs/Cargo.toml crates/jobs/
COPY core-rs/crates/sender/Cargo.toml crates/sender/
COPY core-rs/crates/server/Cargo.toml crates/server/
COPY core-rs/crates/store/Cargo.toml crates/store/
RUN for crate in crates/*/; do mkdir -p "${crate}src" && touch "${crate}src/lib.rs"; done \
    && echo 'fn main() {}' > crates/server/src/main.rs \
    && cargo build --release --locked --bin ferropost \
    && rm -rf crates/*/src
COPY core-rs/crates crates
# The copied files can be older than the empty crates built above; touch
# them so that cargo compiles the real ones.
RUN find crates -name '*.rs' -exec touch {} + \
    && cargo build --release --locked --bin ferropost \
    && mv target/release/ferropost /usr/local/bin/ferropost \
    && rm -rf target

# --- The image ------------------------------------------------------------------------------
FROM ${RUNTIME_IMAGE}

LABEL org.opencontainers.image.title="Ferropost core" \
      org.opencontainers.image.description="Ferropost's web console, API and background jobs" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

RUN apk add --no-cache \
    bash \
    ca-certificates \
    curl \
    supervisor \
    rsyslog \
    tzdata \
    busybox-extras \
    postgresql-client \
    fail2ban \
    iptables \
    ipset \
    && rm -rf /var/cache/apk/*

COPY Dockerfiles/core/stop-supervisor.sh /stop-supervisor.sh
COPY Dockerfiles/core/core.sh /core.sh
COPY Dockerfiles/core/restart_fail2ban.sh /restart_fail2ban.sh
COPY Dockerfiles/core/supervisord.conf /etc/supervisor/supervisord.conf
COPY Dockerfiles/core/fail2ban.conf /etc/fail2ban/fail2ban.conf
# manifest: the console version shown in Settings
COPY core/manifest /opt/billionmail/core/manifest
COPY core/languages /opt/billionmail/core/languages
COPY core/template /opt/billionmail/core/template
COPY core/public/html /opt/billionmail/core/public/html
COPY --from=console /src/core/frontend/dist /opt/billionmail/core/public/dist
# cargo made the binary executable already.
COPY --from=core /usr/local/bin/ferropost /opt/billionmail/core/ferropost
RUN chmod +x /stop-supervisor.sh /core.sh /restart_fail2ban.sh

ENTRYPOINT ["/core.sh"]
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
