#!/bin/bash
# Run test coverage using cargo-llvm-cov in Docker
set -euo pipefail

cd "$(dirname "$0")/../.."

docker run --rm \
  -v "$PWD:/app" \
  -w /app \
  -e CARGO_HOME=/app/target/.cargo-docker \
  rust:1.88-bookworm \
  bash -c '
    rustup component add llvm-tools-preview &&
    cargo install cargo-llvm-cov --locked &&
    cargo llvm-cov --workspace --ignore-filename-regex "tests/" --html --output-dir /app/target/coverage
  '

echo "Coverage report: target/coverage/html/index.html"
