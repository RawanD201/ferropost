#!/bin/sh
# Builds static (musl) ferropost binaries for the core image.
#
# Usage: sh core-rs/build.sh [all|x86|arm]      (same arguments as core/go-build.sh)
#
# Output: core/ferropost-amd64 and/or core/ferropost-arm64, which
# Dockerfiles/core/Dockerfile copies next to the Go binary.
# Building arm64 on an x86 host needs QEMU binfmt (docker run --privileged
# --rm tonistiigi/binfmt --install arm64).

set -eu

PLATFORMS=${1:-all}
RUST_IMAGE=${RUST_IMAGE:-rust:1.90-alpine}
HERE=$(cd "$(dirname "$0")" && pwd)
OUT="$HERE/../core"

case "$PLATFORMS" in
  all) ARCHES="amd64 arm64" ;;
  x86) ARCHES="amd64" ;;
  arm) ARCHES="arm64" ;;
  *) echo "usage: $0 [all|x86|arm]" >&2; exit 1 ;;
esac

for arch in $ARCHES; do
  echo ">> building ferropost for linux/$arch with $RUST_IMAGE"
  docker run --rm --platform "linux/$arch" \
    -v "$HERE":/src -w /src \
    -v ferropost-cargo-$arch:/usr/local/cargo/registry \
    -e CARGO_TARGET_DIR="/src/target/docker-$arch" \
    "$RUST_IMAGE" \
    sh -c 'apk add --no-cache musl-dev >/dev/null && cargo build --release --locked --bin ferropost'
  cp "$HERE/target/docker-$arch/release/ferropost" "$OUT/ferropost-$arch"
  echo ">> $OUT/ferropost-$arch"
done
