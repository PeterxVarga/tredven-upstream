# Tredven Upstream

**An open-source, local-first upgrade preflight for self-hosted software.**

> **Pre-alpha, read-only prototype.** The new `inspect-git` command verifies named tags and commit objects in an **existing local Git clone**. It does **not** independently authenticate upstream publishers, fetch source over the network, inspect a production runtime, run your application tests, or certify a safe upgrade. Do not use its status as permission to deploy.

[MIT license](LICENSE) · Rust 2024 · Works without an account, Docker socket or hosted service.

## What works today

- One Rust binary to inspect a **local JSON file or stdin** and emit a machine-readable JSON or Markdown review.
- Compare caller-supplied commits with explicit unverified provenance, or use `inspect-git` to resolve two named tags and obtain a complete **local** changed-path list (no Git checkout or fetch).
- Consume explicit check results (`passed`, `failed`, `not_run`, `unknown`); list at most 25 paths prioritized for **human review**, not semantic breakage certification.
- Fail closed: `BLOCKED` for failed checks and contradictory source claims, `REVIEW` for a declared version movement that needs human qualification, `UNKNOWN` for missing evidence.
- All patch/merge/deploy/send/provider-write/payment/release authority flags are **always false**.
- Stable, input-bounded, portable source with no runtime network calls or background process.

**NOT supported yet:** independent remote tag/publisher verification; automatic repository cloning/fetching; third-party adapter registration; automatic migration discovery or execution; Docker/Podman/Kubernetes access; integration-test orchestration; reliable assessment of a live self-hosted application; reporting true production readiness; managed fleet or billing.

## Run

Requires a local Rust toolchain (1.100.0 pinned for contributors). The `inspect-git` command additionally requires an installed `git` executable and an existing local Git repository with named tags. Other toolchains may compile because the crate's minimum Rust version is 1.85.

```bash
cargo test --locked --all-targets
cargo run --locked -- inspect --input fixtures/upgrade-review.json
cargo run --locked -- inspect --input fixtures/upgrade-review.json --format markdown
cargo run --locked -- inspect --input fixtures/upgrade-blocked.json
# BLOCKED returns exit code 2, as an intentional safety signal.
```

For an **existing local Git clone** (these are example tag names, not a promise your repo has them):

```bash
cargo run --locked -- inspect-git \
  --repo /absolute/path/to/your/clone \
  --project example \
  --from v1.0.0 \
  --to v1.1.0 \
  --format markdown
```

This command uses the installed local Git executable without any shell interpolation, hooks, external diff tools, network requests, Docker or provider credentials. It does not modify the checkout; local uncommitted files do **not** contribute to the two-tag diff. It checks local commit identities, **not** whether they correspond to signed or currently deployed official releases. Non-UTF-8 Git filenames and overly large diffs are rejected rather than silently accepted as complete.

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

There is **no telemetry or required cloud account**. For `inspect`, any `source_verified: true` field means *the caller asserts this*. For `inspect-git`, the report identifies its actual origin as `LOCAL_GIT_OBJECTS_REMOTE_UNATTESTED`. Neither path independently verifies a remote publisher, production runtime, database rollback, business correctness or authorized upgrade.

## How the prototype decides

| Input evidence | Decision | What it means |
| --- | --- | --- |
| Source identity mismatch, failed check, contradictory same-commit diff | `BLOCKED` | Do not upgrade; inspect the failure |
| Caller asserts a verified, different upstream commit with no hard block | `REVIEW` | Review changed surface and run isolated runtime tests |
| Exact commit/source identity or runtime proof is missing | `UNKNOWN` | Not enough evidence, never an upgrade clearance |

No current combination of inputs produces `READY`: that status would require independently obtained source/runtime evidence and an explicit external approval boundary. A green Cargo test does not establish a safe upgrade for your application.

The output is **advisory only**. A `REVIEW` decision may remain appropriate even after local tag comparison because there are no independently executed runtime/rollback checks. Path categories and review candidates are heuristics, not proof of a breaking change. See the [source-pinned public Git validation](docs/R2_SOURCE_QUALIFICATION.md).

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
