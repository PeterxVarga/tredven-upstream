# Tredven Upstream

**An open-source, local-first upgrade preflight for self-hosted software.**

> **Pre-alpha, read-only prototype.** This version evaluates only **caller-supplied** release evidence. It does **not** fetch a repository, verify a Git commit, inspect a production runtime, test your real application, or certify a safe upgrade. Do not use its status as permission to deploy.

[MIT license](LICENSE) · Rust 2024 · Works without an account, Docker socket or hosted service.

## What works today

- One Rust binary to inspect a **local JSON file or stdin** and emit a machine-readable JSON or Markdown review.
- Compare two caller-supplied Git commit identities; highlight an incomplete or truncated diff and classify potentially sensitive changed paths.
- Consume explicit check results (`passed`, `failed`, `not_run`, `unknown`).
- Fail closed: `BLOCKED` for failed checks and contradictory source claims, `REVIEW` for a declared version movement that needs human qualification, `UNKNOWN` for missing evidence.
- All patch/merge/deploy/send/provider-write/payment/release authority flags are **always false**.
- Stable, input-bounded, portable source with no runtime network calls or background process.

**NOT supported yet:** live GitHub or Git tag inspection; third-party adapter registration; automatic migration discovery or execution; Docker/Podman/Kubernetes access; integration-test orchestration; reliable assessment of any concrete self-hosted application; reporting true production readiness; managed fleet or billing.

## Run

Requires a local Rust toolchain (1.100.0 pinned for contributors). Other toolchains may compile because the crate's minimum Rust version is 1.85.

```bash
cargo test --locked --all-targets
cargo run --locked -- inspect --input fixtures/upgrade-review.json
cargo run --locked -- inspect --input fixtures/upgrade-review.json --format markdown
cargo run --locked -- inspect --input fixtures/upgrade-blocked.json
# BLOCKED returns exit code 2, as an intentional safety signal.
```

Example (report excerpt):

```json
{
  "decision": "REVIEW",
  "evidence_origin": "CALLER_SUPPLIED_UNVERIFIED",
  "compare_coverage": "complete",
  "production_ready": false,
  "authority": {
    "patch": false,
    "merge": false,
    "deploy": false,
    "send": false,
    "provider_writes": false,
    "paid_queries": false,
    "release": false
  }
}
```

There is **no telemetry or required cloud account**. Any `source_verified: true` field means *the caller asserts this*, not that this CLI has checked an upstream server.

## How the prototype decides

| Input evidence | Decision | What it means |
| --- | --- | --- |
| Source identity mismatch, failed check, contradictory same-commit diff | `BLOCKED` | Do not upgrade; inspect the failure |
| Caller asserts a verified, different upstream commit with no hard block | `REVIEW` | Review changed surface and run isolated runtime tests |
| Exact commit/source identity or runtime proof is missing | `UNKNOWN` | Not enough evidence, never an upgrade clearance |

No current combination of inputs produces `READY`: that status would require independently obtained source/runtime evidence and an explicit external approval boundary. A green Cargo test does not establish a safe upgrade for your application.

The output is **advisory only**. A `REVIEW` decision may remain appropriate even after all declared checks pass because their coverage is neither complete nor independently verified.

## Development direction

Earlier internal compatibility checks established the behaviors we aim to make generally usable: exact source provenance, scoped change detection, failure on unverified safety patches and honest distinction between historical isolated tests and an actually qualified running system. The **private original source and environment-specific paths or receipts are deliberately not part of this repository**.

We intend to replace the existing Python/Node compatibility-gate logic gradually with a standalone Rust library and CLI, while respecting exact negative-case semantics. A local legacy runner remains the comparison baseline, not code to be blindly copied or published. See [migration strategy](docs/RUST_PORTING.md).

An optional hosted product might eventually maintain verified compatibility-rule feeds and multi-instance monitoring. This repository will remain useful for free and without that service. **No paid product or verified external adoption is claimed.**

## Contributing

We welcome documented, reproducible upgrade examples with **synthetic or explicitly public data**. Never file issues containing private configs, tokens, internal endpoints, customer records or credentials. Prefer a version-pinned minimal fixture and the expected decision over a screenshot of production internals.

Run locally:

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
```

We intentionally have **no GitHub Actions workflow yet**. This is a public repository and it would be unsafe to run untrusted PR code on an owner-controlled, non-ephemeral self-hosted runner. A safe isolated public-PR CI solution is a separate engineering decision.

## Scope and safety

No deployment, patching, remote execution, billing, secret collection or provider writes. Compare data and test outcomes are untrusted input and **never authorization**. See [security](SECURITY.md).

## License

MIT. Copyright © 2026 Tredven Upstream contributors.
