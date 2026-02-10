# AGENTS.md

## Mission

Flashnet is the first permissionless, non-custodial exchange on Bitcoin. We settle natively on Spark, a Bitcoin L2 with instant finality and near-zero fees. No bridges, no wrapped assets, no custodians.

This repository is the **settlement layer** -- the core execution engine that sits between users and the Spark protocol. It processes swaps, manages liquidity, coordinates validators, and settles transfers atomically on Spark.

The system runs inside a Trusted Execution Environment (TEE) for cryptographic isolation. Validators provide distributed trust through FROST threshold signatures -- they witness intent and co-sign settlement, but never custody funds. Keys stay client-side.

Core capabilities:
- Automated Market Maker execution (constant-product and concentrated liquidity)
- Atomic multi-hop swaps across liquidity pools
- FROST threshold signatures for distributed key management
- Bitcoin and token settlement over Spark with sub-second finality

## Architecture Vision

### Core vs. Apps

The central architectural principle is **decoupling apps from core infrastructure**. Adding a new trading primitive (a new AMM variant, an orderbook, lending) should not require touching core.

**Core** is the infrastructure any app needs:
- Spark integration (transfers, claims, leaf management)
- FROST signing and key derivation
- gRPC transport and processor pipeline
- Storage (PostgreSQL, Redis)
- Health monitoring and graceful shutdown
- Operation state tracking and retry/recovery

**Apps** are standalone features built on core:
- AMM V2 (constant-product pools)
- AMM V3 (concentrated liquidity positions)
- Future: orderbook, lending, or any new trading primitive

The boundary is enforced through traits. Core defines interfaces; apps implement them. No app-specific logic leaks into core. If two apps need the same capability, it gets extracted into core behind a trait.

### System Topology

```
Client -> Settlement (validator coordination) -> TEE (execution) -> Spark Operators
                                                   |
                                              Validators (FROST co-signers)
```

- **TEE**: Runs the processor pipeline and executes all trading logic inside a secure enclave
- **Settlement**: gRPC gateway that coordinates validator signatures before forwarding to TEE
- **Validators**: Distributed signers that provide threshold trust without custody

### External Repositories

- **Settlement Protos**: https://github.com/polarityorg/settlement-protos/
- **Validators**: https://github.com/polarityorg/flashnet-validators/
- **AMM Gateway**: https://github.com/polarityorg/flashnet-services/

## Code Standards

All contributions must meet these standards. Code that doesn't will be rejected.

### First Principles

- **Understand before writing.** Read existing code in the area you're modifying. Understand the patterns, the "why" behind decisions, and the invariants that must hold.
- **Solve the actual problem.** Don't add abstractions for hypothetical future requirements. Write code that solves today's problem cleanly.
- **Question complexity.** If something feels complicated, it probably is. Step back and find the simpler approach.

### Clean Code

- **Small, focused functions.** Each function does one thing. If you can't describe it in one sentence, split it.
- **Explicit over implicit.** Use explicit types, explicit error handling, explicit lifetimes where they clarify intent.
- **Meaningful names.** Variables and functions should describe what they are/do. No `temp`, `data`, `handle` without context.
- **No dead code.** Remove unused imports, functions, and modules. Don't comment out code "for later."

### Production Readiness

- **Error handling is not optional.** Every `?` should be intentional. Use `eyre` for application errors, custom error types for library boundaries.
- **Logging at appropriate levels.** `error!` for failures requiring investigation, `warn!` for recoverable issues, `info!` for operational visibility, `debug!` for development.
- **Instrument critical paths.** Use tracing spans for operations that cross async boundaries or involve I/O.
- **Handle cancellation.** Respect `CancellationToken` signals. Clean up resources on shutdown.
- **Minimize heap allocations.** Prefer stack-allocated, fixed-size types. Use `Copy` types where possible. Avoid `Vec`, `String`, `Box` in hot paths unless the size is genuinely dynamic. When heap allocation is necessary, pre-allocate with known capacity.

### No Duplication

- **DRY with purpose.** Extract shared logic when there's a clear abstraction. Three occurrences is the threshold.
- **Use existing utilities.** Check type crates and trait definitions before writing new ones.
- **Consistent patterns.** Follow existing patterns in the codebase for similar operations (channel communication, error handling, logging).

### Boundary Discipline

- **Traits at crate boundaries.** Core defines interfaces; apps implement them. Implementations can change without breaking consumers.
- **No app logic in core.** If you're adding pool-type-specific code to core infrastructure, you're doing it wrong. Abstract it behind a trait.
- **Composition over inheritance.** Prefer struct composition and trait bounds over complex type hierarchies.
- **Configuration over hardcoding.** Use config structs for tunable parameters. Provide sensible defaults.

### Rust Idioms

```rust
// Prefer early return with ?
let result = operation().await?;
process(result);

// Prefer iterators when intent is clear
let processed: Vec<_> = items.iter().filter(|x| x.valid).map(|x| x.value).collect();

// Use type aliases for complex types
type PoolId = Uuid;
type ExchangeResult<T> = Result<T, ExchangeError>;

// Prefer strong types over primitives
struct Amount(u64);  // Not just u64
struct PoolId(Uuid); // Not just Uuid
```

### Code Review Checklist

Before submitting, verify:
- [ ] Types are explicit and correct
- [ ] No duplicated logic
- [ ] Functions are small and focused
- [ ] Error handling is comprehensive
- [ ] Tests cover new code paths
- [ ] `cargo clippy` passes with no warnings
- [ ] `cargo fmt` has been run
- [ ] Public APIs have doc comments
- [ ] No app-specific logic in core crates

### Where Detail Belongs

This file is the north star -- mission, architecture, standards. It should not contain anything discoverable by reading the code.

- **Function signatures, request flows, handler lists**: doc comments and module-level `//!` documentation in the source
- **Configuration examples**: comments in the config files themselves
- **Debugging runbooks**: a separate operational document, not here

## Development

### Build

```bash
cargo build                        # Build all workspace members
cargo build -p <package>           # Build specific package
cargo build --release              # Release build
```

### Lint and Format

```bash
cargo clippy                       # Strict pedantic/nursery linting
cargo fmt                          # Format code
cargo fmt -- --check               # Check formatting without changes
```

### Test

```bash
# Unit tests (fast, no containers)
./scripts/tests/1-run-unit-tests.sh

# Integration tests (requires containers)
./scripts/tests/2-run-integration-tests.sh

# Leaf selector tests
./scripts/tests/3-run-leaf-selector-tests.sh

# Spark module tests
TEST_PG_MAX_CONNS=100 ./scripts/tests/4-run-spark-module-tests.sh

# E2E tests (requires full stack)
VALIDATOR_LOCAL_PATH=../flashnet-validators ./scripts/tests/5-run-e2e-tests.sh
```

### Local Development

```bash
# Credentials
export GITHUB_PAT="<your_github_token>"
export CARGO_REGISTRIES_POLARITY_TOKEN="Bearer <your_cargo_token>"

# Start full stack (Redis, Postgres, TEE, Settlement, Validators)
./infrastructure/dev/scripts/start-all-services.sh

# Run TEE locally
RUST_LOG=info CONFIG_FILE="./config/tee/tee.local.config.toml" cargo run --package tee
```

### Database

```bash
export DATABASE_URL=postgres://postgres:postgres@localhost:5434/settlement_tee
cargo sqlx migrate run             # Run migrations
cargo sqlx prepare                 # Generate offline query data
```

## Conventions

### Commits

We use [Conventional Commits](https://www.conventionalcommits.org/) with [release-plz](https://release-plz.dev/).

| Type | Bump | Example |
|------|------|---------|
| `feat` | Minor | `feat(amm): add concentrated liquidity pools` |
| `fix` | Patch | `fix(spark): resolve claim timeout on token transfers` |
| `feat!` / `fix!` | Major | `feat!: redesign settlement API` |
| `docs`, `refactor`, `test`, `chore` | None | `refactor(core): extract storage trait` |

Scopes: `settlement`, `tee`, `core`, `amm`, `spark`, `crypto`

### Pull Requests

- PR titles become commit messages (squash merge)
- Each app versions independently via release-plz
- Don't manually edit versions in `Cargo.toml`

### Key Dependencies

- **Private Registry**: `polarity` for flashnet-specific crates
- **gRPC**: tonic (pinned for Spark operator compatibility)
- **Database**: PostgreSQL via sqlx, Redis via deadpool
- **Cryptography**: FROST via `frost-secp256k1-tr-unofficial`, ECDSA/Schnorr via `k256`
- **Async**: tokio runtime with channel-based processor communication
