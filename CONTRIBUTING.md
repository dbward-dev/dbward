# Contributing to dbward

Thank you for your interest in contributing to dbward!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/dbward.git`
3. Create a branch: `git checkout -b feat/my-feature`
4. Make your changes
5. Run tests: `cargo test --workspace`
6. Submit a pull request

## Development Setup

```bash
# Prerequisites
# - Rust 1.88+
# - Docker (for integration tests)

# Build
cargo build

# Run tests (unit tests, no Docker needed)
cargo test --workspace

# Run integration tests (requires Docker for PostgreSQL)
cargo test --workspace -- --ignored

# Lint
cargo clippy --workspace -- -D warnings

# Format
cargo fmt --all
```

## Code Style

- Follow existing patterns in the codebase
- Comments explain **why**, not what
- All code, comments, commit messages, and logs in English
- Use `cargo fmt` and `cargo clippy` before committing

## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>[(scope)]: <description>

feat(server): add token TTL support
fix(agent): handle connection timeout gracefully
docs: update getting-started guide
chore: update dependencies
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `perf`, `ci`, `build`

## Pull Requests

- Keep PRs focused on a single change
- Include tests for new functionality
- Update documentation if behavior changes
- Ensure CI passes (fmt + clippy + test + cargo-deny)

## Testing

- New public types/functions must have tests
- DB tests use `testcontainers-rs` (PostgreSQL)
- Network-dependent tests use `#[ignore]`
- Run `cargo test --workspace` before submitting

## Architecture

See [docs/architecture.md](docs/architecture.md) for the system design.

Key principles:
- Client never touches the database
- Server never touches the database
- Agent is the only component with DB credentials
- All operations go through the approval workflow

## License

By contributing, you agree that your contributions will be licensed under:
- `dbward-server`: [BSL 1.1](LICENSE-BSL) (converts to Apache-2.0 on 2029-05-08)
- All other crates: [Apache-2.0](LICENSE-APACHE) OR [MIT](LICENSE-MIT)

## Breaking Change Policy

While dbward is pre-1.0 (v0.x):

- **Patch versions (0.1.x)**: No breaking changes. Config files, API, and CLI remain compatible.
- **Minor versions (0.x.0)**: May introduce breaking changes. Always documented in CHANGELOG.
- **SQLite schema**: Forward-compatible only. Columns are added, never removed. Rollback is possible by restoring the auto-created backup.
- **Config files**: New fields always have default values. Existing TOML files continue to work without modification.

## Questions?

Open a [GitHub Discussion](https://github.com/metapox/dbward/discussions) or file an issue.
