# syntax=docker/dockerfile:1.7

FROM rust:1.88-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates/dbward-domain/Cargo.toml crates/dbward-domain/Cargo.toml
COPY crates/dbward-app/Cargo.toml crates/dbward-app/Cargo.toml
COPY crates/dbward-infra/Cargo.toml crates/dbward-infra/Cargo.toml
COPY crates/dbward-driver/Cargo.toml crates/dbward-driver/Cargo.toml
COPY crates/dbward-api-types/Cargo.toml crates/dbward-api-types/Cargo.toml
COPY crates/dbward-migrate/Cargo.toml crates/dbward-migrate/Cargo.toml
COPY crates/dbward-server/Cargo.toml crates/dbward-server/Cargo.toml
COPY crates/dbward-agent/Cargo.toml crates/dbward-agent/Cargo.toml
COPY crates/dbward-cli/Cargo.toml crates/dbward-cli/Cargo.toml

RUN mkdir -p \
    crates/dbward-domain/src \
    crates/dbward-app/src \
    crates/dbward-infra/src \
    crates/dbward-driver/src \
    crates/dbward-api-types/src \
    crates/dbward-migrate/src \
    crates/dbward-server/src \
    crates/dbward-agent/src \
    crates/dbward-cli/src \
 && for d in domain app infra driver api-types migrate; do \
      printf 'pub fn placeholder() {}\n' > crates/dbward-$d/src/lib.rs; \
    done \
 && printf 'pub fn placeholder() {}\nfn main() {}\n' > crates/dbward-server/src/lib.rs \
 && printf 'fn main() {}\n' > crates/dbward-server/src/main.rs \
 && printf 'pub fn placeholder() {}\nfn main() {}\n' > crates/dbward-agent/src/lib.rs \
 && printf 'fn main() {}\n' > crates/dbward-agent/src/main.rs \
 && printf 'fn main() {}\n' > crates/dbward-cli/src/main.rs

# Pre-build dependencies (cached unless Cargo.toml/Cargo.lock change)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release 2>/dev/null || true

COPY . .

# Rebuild our crates only
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo clean --release \
      -p dbward -p dbward-domain -p dbward-app -p dbward-infra \
      -p dbward-driver -p dbward-api-types -p dbward-migrate \
      -p dbward-server -p dbward-agent \
 && cargo build --release \
 && cp /app/target/release/dbward /usr/local/bin/dbward \
 && cp /app/target/release/dbward-server /usr/local/bin/dbward-server \
 && cp /app/target/release/dbward-agent /usr/local/bin/dbward-agent

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -r -g 10001 dbward \
 && useradd -r -u 10001 -g dbward -d /data -s /sbin/nologin dbward \
 && mkdir -p /data && chown dbward:dbward /data

WORKDIR /workspace

COPY --from=builder /usr/local/bin/dbward /usr/local/bin/dbward
COPY --from=builder /usr/local/bin/dbward-server /usr/local/bin/dbward-server
COPY --from=builder /usr/local/bin/dbward-agent /usr/local/bin/dbward-agent

USER dbward:dbward
VOLUME /data

ENTRYPOINT ["dbward"]
