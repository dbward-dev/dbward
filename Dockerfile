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

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --package dbward --bin dbward || true

COPY . .

# Touch all source files so cargo detects changes from dummy sources
RUN find crates -name '*.rs' -exec touch {} +

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --package dbward --bin dbward \
 && install -Dm755 target/release/dbward /out/dbward

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY --from=builder /out/dbward /usr/local/bin/dbward

ENTRYPOINT ["dbward"]
