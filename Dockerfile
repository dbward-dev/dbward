# syntax=docker/dockerfile:1.7

FROM rust:1.88-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates/dbward-core/Cargo.toml crates/dbward-core/Cargo.toml
COPY crates/dbward-migrate/Cargo.toml crates/dbward-migrate/Cargo.toml
COPY crates/dbward-server/Cargo.toml crates/dbward-server/Cargo.toml
COPY crates/dbward-agent/Cargo.toml crates/dbward-agent/Cargo.toml
COPY crates/dbward-cli/Cargo.toml crates/dbward-cli/Cargo.toml

RUN mkdir -p \
    crates/dbward-core/src \
    crates/dbward-migrate/src \
    crates/dbward-server/src \
    crates/dbward-agent/src \
    crates/dbward-cli/src \
 && printf '%s\n' 'pub fn placeholder() {}' > crates/dbward-core/src/lib.rs \
 && printf '%s\n' 'pub fn placeholder() {}' > crates/dbward-migrate/src/lib.rs \
 && printf '%s\n' 'pub fn placeholder() {}' > crates/dbward-server/src/lib.rs \
 && printf '%s\n' 'pub fn placeholder() {}' > crates/dbward-agent/src/lib.rs \
 && printf '%s\n' 'fn main() {}' > crates/dbward-cli/src/main.rs

# Pre-build dependencies only (cached unless Cargo.toml/Cargo.lock change)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --package dbward --bin dbward 2>/dev/null || true

COPY . .

# Force recompile of our crates using cargo clean -p (proper invalidation).
# Third-party deps remain cached in the mount.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo clean --release \
      -p dbward -p dbward-core -p dbward-migrate -p dbward-server -p dbward-agent \
 && cargo build --release --package dbward --bin dbward \
 && cp /app/target/release/dbward /usr/local/bin/dbward

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -r -g 10001 dbward \
 && useradd -r -u 10001 -g dbward -d /data -s /sbin/nologin dbward \
 && mkdir -p /data && chown dbward:dbward /data

WORKDIR /workspace

COPY --from=builder /usr/local/bin/dbward /usr/local/bin/dbward

USER dbward:dbward
VOLUME /data

ENTRYPOINT ["dbward"]
