# Contributing

Thanks for helping make SecuScan better. Before your first PR: read
[README](README.md), [ARCHITECTURE](docs/ARCHITECTURE.md), and — if you're adding
plugins — [PLUGIN_DEVELOPMENT](docs/PLUGIN_DEVELOPMENT.md).

## Ground rules

- **Authorized use only** — contributions must not weaken the consent gate, target
  policy, or audit log without an explicit, documented design discussion.
- Every behavior change ships with tests. Bug fixes ship with a regression test that
  fails before the fix.
- No plugin-supplied code execution. Parsers stay declarative; if you need something a
  declarative parser cannot express, propose a native scanner instead.

## Development setup

```bash
git clone … && cd SecuScan-v2
cargo build --workspace
cargo test --workspace --locked
cd frontend && npm ci && npm run typecheck && npm test
```

## Quality gates (CI enforces these)

The CI pipeline runs Rust formatting, Clippy, Rust tests and plugin validation as **independent jobs**, so an early formatting failure does not hide results from the other checks. All jobs must pass before merging; a successful job does not override a failed job. Docker and product E2E also run separately, and can expose independent failures.

For a full local check, use `make verify`. To fix formatting drift, run `make fmt` and commit the resulting changes; do not weaken or skip the formatting check.

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo run -q -p secuscan-cli --locked -- plugins validate ./plugins
cd frontend && npm run typecheck && npm test && npm run build
# after unit jobs pass: release server + SPA, then product-surface E2E
cargo build --locked --release --bin secuscan-server
node scripts/verify.mjs
```

Parser fixtures for the power-engine plugins live in
`crates/core/tests/plugin_parsers.rs`. A new CLI plugin that emits findings
should add a sample of its real output there.

## Adding a plugin

1. Create `plugins/<id>.toml` following the reference (start by copying a similar
   shipped plugin).
2. `cargo run -p secuscan-cli -- plugins validate plugins/<id>.toml` must pass.
3. Add fixture output + parser assertions if you added parsing features.
4. Keep the safety level honest and `allowed_targets` conservative for network-layer
   tools.

## Commit style

Conventional-ish: `feat:` / `fix:` / `docs:` / `refactor:` / `test:` with an imperative
subject line. The [review log](docs/REVIEW_LOG.md) documents the audit cycles behind
each release — extend it when you do a hardening pass.
