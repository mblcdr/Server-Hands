#!/bin/sh
# Builds server-hands_<ver>_amd64.deb in a Debian 13 container (same libc as OMV 8), so the binary
# links against the glibc it will run with. Needs a running Docker daemon.
set -eu
cd "$(dirname "$0")/../.."
docker run --rm -v "$PWD":/src -w /src/server debian:13 sh -ec '
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends build-essential curl ca-certificates pkg-config
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null
  . "$HOME/.cargo/env"
  cargo install cargo-deb --locked
  cargo test --workspace --locked
  cargo build --release --workspace --locked
  cargo deb -p handsd --no-build -o /src/server/target/debian/
'
ls -l server/target/debian/*.deb
