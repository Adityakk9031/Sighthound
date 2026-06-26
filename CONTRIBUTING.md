# Contributing to Sighthound

Thanks for your interest in improving Sighthound. This guide covers the build
and contribution workflow.

## Prerequisites

- Rust 1.70+ (install from https://rustup.rs/)
- Git

## Build

```bash
git clone https://github.com/Corgea/Sighthound.git
cd Sighthound
cargo build --release          # binary at target/release/sighthound
```

`cargo build --release` is the command CI gates on and should succeed before
you open a PR.

## Tests

The repository ships three test harnesses (`unit_tests`, `integration_tests`,
and `end_to_end_tests`). They are being realigned to the crate's refactored
rule API — some modules are temporarily disabled and `cargo test` is not yet
fully green, so CI gates on `cargo build --release`. Restoring `cargo test` to
green is tracked in its own PR; contributions that fix a harness are welcome.

```bash
cargo build --release          # the CI-gated command
cargo test --test unit_tests   # a single harness (some modules under repair)
```

### Make targets

| Target           | Action                              |
|------------------|-------------------------------------|
| `make build`     | `cargo build --release`             |
| `make clean`     | clean build artifacts               |
| `make install`   | `cargo install --path .`            |
| `make help`      | list targets                        |

`make test` / `test-unit` / `test-all` invoke `cargo test`, which is under
repair (see above).

## Multi-platform builds

`build_all_platforms.sh` produces Linux x64/arm64 (via Docker + buildx) and a
native macOS binary; the `Dockerfile` provides a containerized build. These
require Docker with buildx.

## Writing rules

Rules are RON (Rusty Object Notation) files under `rules/<lang>/`. See the
[Rule Writing Guide](rules/RULE_WRITING_GUIDE.md) for the rule format and
authoring guidance.

## Pull request workflow

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/your-feature`.
3. Make your changes and add tests where practical.
4. Confirm `cargo build --release` succeeds.
5. Submit a pull request.

By contributing, you agree your contributions are licensed under the MIT
License (see [LICENSE](LICENSE)) and that you will follow our
[Code of Conduct](CODE_OF_CONDUCT.md).
