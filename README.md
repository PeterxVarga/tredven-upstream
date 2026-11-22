# Tredven Upstream

**An open-source, local-first upgrade preflight for self-hosted software.**

> **Pre-alpha, read-only prototype.** `inspect-git` resolves named tags in a **local Git clone**; `inspect-contract` adds **one exactly pinned OpenSEO PostgreSQL migration prerequisite check**. Neither command authenticates an upstream publisher, fetches source, connects to a running database, executes SQL or certifies a safe upgrade.

[MIT license](LICENSE) · Rust 2024 · Works without an account, Docker socket or hosted service.

## What works today

- One Rust binary to inspect a **local JSON file or stdin** and emit a machine-readable JSON or Markdown review.
- Compare caller-supplied commits with explicit unverified provenance, or use `inspect-git` to resolve two named tags and obtain a complete **local** changed-path list (no Git checkout or fetch).
- Consume explicit check results (`passed`, `failed`, `not_run`, `unknown`); list at most 25 paths prioritized for **human review**, not semantic breakage certification.
- One **release-specific, source-pinned** SQL/Drizzle contract checks foreign-key parent columns in the *Git-committed baseline schema* without running the SQL.
- Fail closed: `BLOCKED` for failed checks and contradictory source claims, `REVIEW` for a declared version movement that needs human qualification, `UNKNOWN` for missing evidence.
- Opt-in multi-project watch plans now combine local Git source changes with externally produced CI/security/backup/rollback evidence in one review report. **Caller-supplied check statuses are not independently verified.**
- Native **Trivy JSON v2** and **OSV-Scanner v2 JSON** parsing, usable standalone (`inspect-scan`), inside watch plans, or with local Git from one command (`inspect-upgrade`). The CLI does not execute either scanner, authenticate the author or prove complete scan coverage.
- R7 two-report comparison (`inspect-delta` and Git-tag-bound `inspect-upgrade-delta`), with separate delta and absolute-candidate decisions, strict scope match and no false green from missing scanners.
- All patch/merge/deploy/send/provider-write/payment/release authority flags are **always false**.
- Stable, input-bounded, portable source with no runtime network calls or background process.

**NOT supported yet:** independent remote publisher verification; automatic repository cloning/fetching; general SQL parsing or migration execution; arbitrary third-party adapters; Docker/Podman/Kubernetes access; runtime integration testing; live database schema validation; reporting production readiness; managed fleet or billing.

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

For the **exact public OpenSEO** v0.1.27 → v0.1.31 upgrade (requires an existing local copy of [every-app/open-seo](https://github.com/every-app/open-seo) with both tags):

```bash
cargo run --locked -- inspect-contract \
  --repo /absolute/path/to/your/open-seo-clone \
  --project open-seo \
  --profile open-seo-v0.1.31-stripe-projects-0049 \
  --format markdown
```

This specifically checks `public.user(id)` and `public.organization(id)` in the **original upstream baseline Drizzle snapshot**, after verifying the source release commits and exact migration blob. It does **not** check whether your real database has those tables. Three completely synthetic schema fixtures are included for REVIEW/BLOCKED examples. Details: [R3 migration contract and test proof](docs/R3_OPEN_SEO_STRIPE_CONTRACT.md).

Example (unverified JSON report excerpt):

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

There is **no telemetry or required cloud account**. For `inspect`, any `source_verified: true` field is *caller asserted*. For `inspect-git` and `inspect-contract`, the report source origin is `LOCAL_GIT_OBJECTS_REMOTE_UNATTESTED`. The R3 contract also records whether the checked schema is the Git baseline or an unverified caller-supplied fixture. None of these paths verifies a remote publisher, deployed database, migration execution, rollback or business correctness.

## Read-only upgrade watch plans (R5)

We reuse **Renovate/Diun/Drydock-style workflows**, not their code or privileged actions. Existing tools continue to discover versions, create PRs, scan vulnerabilities and run tests. The Rust CLI now composes a **declarative, explicitly enabled** watchlist with source-bound test artifact references.

```bash
# A deliberately disabled sample; exits 3 because no targets are enabled.
cargo run --locked -- inspect-plan \
  --manifest examples/watch-plan.json \
  --format markdown
```

To inspect real sources, edit a copy of the example: set `enabled: true`, provide an existing **local** Git repo and two real tags. For each declared required check, record its `source_tool`, `status` and, when claiming `passed`, both the exact **candidate commit ID** and an existing local evidence artifact with its SHA-256 digest. The command reads the file but does **not** run OSV-Scanner, Trivy, CI, Renovate, Docker, backups or the source code.

- **BLOCKED / exit 2:** declared failure, artifact digest mismatch, or evidence bound to the wrong target commit.
- **UNKNOWN / exit 3:** source missing, check not run, declared PASS without an intact artifact or exact commit binding, or no opted-in targets.
- **REVIEW / exit 0:** declared evidence is present for the opted-in targets, **not** proof that it is correct, complete or safe to deploy.

The output includes a per-group summary and explicit provenance/unknowns. An artifact hash verifies **bytes only**, not that a scanner actually ran or its findings are true. No state ever grants deployment authority or a verified green production approval. [R5 design, OSS source comparison, limits and acceptance](docs/R5_OSS_WORKFLOW_ADOPTION.md).

## Native scanner evidence — Rust R6

The CLI can now **parse real-format Trivy JSON v2 and OSV-Scanner v2 JSON directly**. This means you do not have to manually invent a PASS/FAIL state for a machine-readable scanner file. The scanner runs **separately**, using the upstream tool and permissions you control; the Rust program only reads local files.

**Try the shipped synthetic fixtures** (no scanners or services started):

```bash
cargo run --locked -- inspect-scan \
  --input fixtures/scanner/trivy-critical.json \
  --scanner trivy-json-v2 \
  --subject 'example/app@sha256:synthetic-candidate' \
  --format markdown
# Synthetic critical vulnerability: BLOCKED, exit code 2.

cargo run --locked -- inspect-scan \
  --input fixtures/scanner/osv-empty.json \
  --scanner osv-scanner-json-v2 \
  --subject Cargo.lock
# Empty results are UNKNOWN, exit code 3; not a false green result.
```

**One-command source + scanner report**, without hand-authoring a manifest:

```bash
# Exact candidate commit (caller-supplied statement about scan provenance):
git -C /absolute/path/to/source rev-parse 'refs/tags/v1.1.0^{commit}'

cargo run --locked -- inspect-upgrade \
  --repo /absolute/path/to/source \
  --project example-app --from v1.0.0 --to v1.1.0 \
  --scanner trivy-json-v2 \
  --scan-report /absolute/path/to/existing/trivy.json \
  --subject 'exact-Trivy-ArtifactName' \
  --scan-commit REPLACE_WITH_40_CHAR_SOURCE_COMMIT \
  --format markdown
```

This reads local Git tags and an existing scanner report, automatically computes the file SHA-256, verifies the stated commit matches the candidate tag, and composes a single watch-plan decision. **It cannot independently prove the scanner ran against that commit**. Local Git is not authenticated as an official remote release; `REVIEW` and CLI exit 0 **never** authorize an upgrade.

The original multi-project `inspect-plan` now supports an optional `scan` object per evidence entry, with `status: "unknown"` (a manual `"passed"` is rejected). Supported formats are `trivy-json-v2` and `osv-scanner-json-v2`. A disabled, safe sample is [examples/watch-plan-native-scanner.example.json](examples/watch-plan-native-scanner.example.json). These are **purely synthetic examples**, not real CVEs or Tredven runtime results. Details and security limitations: [R6 native scanner evidence](docs/R6_NATIVE_SCANNER_EVIDENCE.md).

## R7 — Compare baseline vs candidate scanner findings

Keep the existing scanners. The **read-only Rust** CLI now compares two *already-produced* native Trivy or OSV-Scanner JSON reports. It counts newly introduced, resolved and persistent findings and severity escalations without equating "no new issues" with "safe to upgrade".

```bash
# Included synthetic fixture pair: the candidate introduces one critical finding.
cargo run --locked -- inspect-delta \
  --baseline fixtures/scanner/trivy-clean.json \
  --candidate fixtures/scanner/trivy-critical.json \
  --scanner trivy-json-v2 \
  --subject 'example/app@sha256:synthetic-candidate' \
  --format markdown
# BLOCKED (exit 2); no scanner was executed.

# Or inspect existing local Git tags + both scanner reports in one command:
# Obtain real tag commits from local Git before copying them as explicit assertions.
cargo run --locked -- inspect-upgrade-delta \
  --repo /ABS/PATH/TO/YOUR/GIT/SOURCE \
  --project example-app --from v1.0.0 --to v1.1.0 \
  --baseline /ABS/PATH/TO/OLD/SCANNER.json \
  --candidate /ABS/PATH/TO/NEW/SCANNER.json \
  --scanner osv-scanner-json-v2 --subject Cargo.lock \
  --baseline-commit REPLACE_WITH_40_HEX_BASE_TAG_COMMIT \
  --candidate-commit REPLACE_WITH_40_HEX_CANDIDATE_TAG_COMMIT \
  --format markdown
```

Both reports must describe the *same, structurally comparable scanner scope*. For Trivy, this includes the exact target, class/type, and reported scanner arrays. For OSV-Scanner, this includes the exact `source.path` and `source.type`. Empty/partial/mismatched reports return **UNKNOWN**, with delta counts shown as **null**, not zero. Finding IDs must be well-formed. High/critical, secret and OSV advisory findings in the candidate remain **BLOCKED even when they already existed in the baseline**; the separate delta describes what changed. The CLI emits at most 20 sample new findings (counts remain complete in bounded inputs); it never prints raw secret matches or full scanner descriptions. It does **not** compare package inventories or verify an actual scanner run.

See [R7 decision, OSS alternatives and evidence limits](docs/R7_SCANNER_UPGRADE_DELTA.md). This is not a replacement for the existing [OSV-Scanner PR reporter](https://github.com/google/osv-scanner-action) or vulnerability triage platforms. No scanner execution, network calls, CI triggers, merge, release or deployment occur.

## R8 — Offline local Rust release candidate (no publication)

Build a **local, unsigned, byte-checkable** release candidate from a clean, committed Git source using the existing Rust toolchain and cached Cargo dependencies. This is a local packaging workflow, **not a GitHub release, signature or production-safe grant**.

```bash
# Run from this repository with Rust 1.100.0 and Python 3.11+ available:
python3 -I -B scripts/test_release_candidate.py
python3 -I -B scripts/release_candidate.py build --out output/r8-local-candidate
python3 -I -B scripts/release_candidate.py verify --dir output/r8-local-candidate
```

Requires an **already clean Git commit**, uses Cargo `--offline --locked`, runs fmt/Clippy/all-target tests, builds the optimized Linux binary, and verifies the Cargo source package before packaging. Creates four ignored local files: binary+license+README `.tar.gz`, `.crate` source archive, checksums and a machine-readable source/build manifest. The verifier checks the **exact files, hashes and bounded archive member metadata**, not signature authenticity, GitHub publisher identity or scanner provenance. It will not overwrite an existing candidate. No GitHub Actions workflows, tags or releases are created. The binary is tested only on the machine used to build it. See [R8 exact limitations and acceptance](docs/R8_OFFLINE_RELEASE_CANDIDATE.md).

## R9 — Verify real signed GitHub artifacts (offline by default)

A new **verify-attestation** command delegates cryptographic certificate and SLSA provenance verification to the **official GitHub CLI**, then enforces the exact repository ID, signer workflow, source commit/tag and signed filename/digest. No cryptographic implementation was added to Rust. This is an **artifact provenance check**, not approval to install, run or deploy software.

A real, signed public release from [attested-delivery/rust-template](https://github.com/attested-delivery/rust-template/releases/tag/v0.1.0) was successfully verified both with public online GitHub lookups and with previously downloaded offline bundle/trusted roots. The same signed sample was rejected when its bytes, repository ID, source tag/commit, signing workflow, artifact name, bundle or root differed. The third-party executable was **never executed**.

```bash
# Once the sample artifact, GitHub bundle and trusted root have been
# downloaded into output/r9-public-signed-fixture (see R9 documentation):
cargo run --locked -- verify-attestation \
  --artifact output/r9-public-signed-fixture/rust_template-0.1.0-linux-amd64 \
  --policy examples/r9-public-attestation-policy.example.json

# For a real, independently signed Trivy JSON file, use the SAME policy gate:
cargo run --locked -- inspect-attested-scan \
  --artifact /ABS/PATH/TO/SIGNED/TRIVY.json \
  --policy /ABS/PATH/TO/OWNER-MAINTAINED-POLICY.json \
  --scanner trivy-json-v2 \
  --subject 'EXACT_TRIVY_ArtifactName'
```

**Important:** the included public signed sample is a release **binary**, not a scanner report. `inspect-attested-scan` will return UNKNOWN for that real signed binary because its content is not Trivy/OSV JSON. **An authenticated scanner file is not proof that a scanner executed**, covered the right source or used a fresh vulnerability database. Our previous local R8 Rust candidate also remains unsigned.

Offline mode requires an existing local attestation **bundle** and trusted root from a separately authenticated source, and never silently falls back to online. `--online` explicitly permits read-only GitHub API lookups. An offline custom root is caller-supplied; its matching hash alone does not establish trust. All output retains `production_ready: false`, `release_authorized: false` and `scanner_execution_verified: false`. See [R9 real signed verification, reproducible fixture, security policy and falsification](docs/R9_REAL_GITHUB_ATTESTATION.md).

## How the prototype decides

| Input evidence | Decision | What it means |
| --- | --- | --- |
| Source identity mismatch, failed check, contradictory same-commit diff | `BLOCKED` | Do not upgrade; inspect the failure |
| Caller asserts a verified, different upstream commit with no hard block | `REVIEW` | Review changed surface and run isolated runtime tests |
| Exact commit/source identity or runtime proof is missing | `UNKNOWN` | Not enough evidence, never an upgrade clearance |

No current combination of inputs produces `READY`: that status would require independently obtained source/runtime evidence and an explicit external approval boundary. A green Cargo test does not establish a safe upgrade for your application.

The output is **advisory only**. `REVIEW` remains appropriate after local tag and migration contract checks because there are no executed runtime/rollback checks. Missing required columns in a supplied synthetic snapshot produce `BLOCKED` **for that snapshot**, not a claim about any live database. Source paths are heuristics, not proven breakages. See [R2 Git source qualification](docs/R2_SOURCE_QUALIFICATION.md) and [R3 contract validation](docs/R3_OPEN_SEO_STRIPE_CONTRACT.md).

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
