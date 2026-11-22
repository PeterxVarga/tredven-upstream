# R5 — OSS feature adoption research and source-bound watch plan

Date: 2026-11-22
Scope: Tredven Upstream open-source Rust CLI only.
Implementation branch: feat/oss-evidence-plan-r5-20261122.
Decision: borrow proven workflows, do not copy code or recreate incumbent update systems.

## Why this integration was selected

The user requested adopting the most useful *core operation* of similar OSS upgrade tools. There are at least three viable routes:

A. Replace Renovate, Drydock, OSV-Scanner, Trivy and container/registry update clients with an all-in-one Rust daemon. Rejected. This repeats active mature ecosystems, entails Docker/provider privileges, a patch/rollback blast radius, security feeds and persistent infrastructure that are not justified by paid or internal evidence.

B. Rewrite the prior release-specific Drizzle FK prototype into a generic SQL migration interpreter. Rejected by R4 counterfactual: a 43-line, dependency-free Node example classified all four chosen cases equally, and no prevented real migration incident was demonstrated.

C. **Selected:** use the incumbents as producers and introduce a source-pinned, opt-in, offline Rust evidence *consumer* which composes their reports and exposes missing approvals as UNKNOWN. The work is one meaningful vertical improvement to the existing CLI; no external scanner or provider needs to be installed to test it.

D. Do nothing except maintain the current Git diff CLI. Lower risk, but no ability to assess an actual stack across CI, security, backup and rollback evidence, so this option misses a user-facing capability.

This is not commercial validation and does not change paid hypothesis HOLD. It also does not override existing private Tredven internal integration boundaries.

## Source-verified OSS comparison

All names below are independently implemented ecosystems. No code was copied, vendored, forked or relicensed; only high-level feature patterns were reimplemented in independently written Rust. Renovate is AGPL-3.0-only, so this is particularly important for the MIT-licensed public Rust project: no Renovate implementation or other upstream code has been transplanted.

| Upstream OSS | Main verified workflow | Selected reuse | Deliberately excluded |
| --- | --- | --- | --- |
| Renovate | Dependency source/manager support, grouping and dependency dashboard, changelogs, PRs, optional dry run | Target grouping and reuse of its existing update discovery rather than recoding registries | No PR authoring, version crawlers, merging, backend or release confidence score |
| Dependabot Core | Dependency manifests, update candidates, dependency-specific compatibility context | Reuse its PR/test outputs as external evidence when exported | No alternative GitHub bot |
| Diun | User-selected container/image watchers, digest/tag change alerts | Explicit opt-in enabled=true; disabled items are never opened | No Docker socket or notifications/schedule |
| Drydock | Dry-run and policies around health, backup, rollback, container update | Non-mutating requirements for health/backup/rollback with fail-closed missing evidence | No container control, auto-updates, rollback execution |
| OSV-Scanner | Vulnerability and lockfile analysis with structured output | Source-tool labels and local artifact SHA-256 receipts for opt-in external scanner evidence | No OSV vulnerability database replication or scanner invocation |
| Trivy | SBOM, image/dependency scans and machine-readable reports | Accept third-party scanner files as opaque, integrity-checked evidence | No duplicate vulnerability engine or remote registry access |
| OpenRewrite | Composable framework migration recipes | Keep rules versioned, explicit and anchored to a source pair | No downloaded code execution or auto-mutation |
| Watchtower | Automatic Docker image updates | **Not adopted**: update automation is out of scope, original repository archived in Dec 2025 | No background updater |

Original-source references reviewed 2026-11-22:
- https://docs.renovatebot.com/bot-comparison/
- https://docs.renovatebot.com/self-hosted-configuration/
- https://github.com/dependabot/dependabot-core
- https://crazymax.dev/diun/providers/docker/
- https://getdrydock.com/docs/v1.8/configuration/rollback
- https://getdrydock.com/docs/v1.9/getting-started
- https://google.github.io/osv-scanner/usage/scan-source
- https://google.github.io/osv-scanner/output/
- https://trivy.dev/docs/latest/configuration/reporting/
- https://docs.openrewrite.org/concepts-and-explanations/recipes
- https://github.com/containrrr/watchtower (archived 2025-12-17)

## Implemented R5 capability

New command:

    tredven-upstream inspect-plan --manifest examples/watch-plan.json --format markdown

The example watch-plan contains *disabled* targets by default. Enable a target only after changing its repo path to an existing local Git clone and supplying two valid local tags.

Manifest schema: tredven.upstream.watch-plan.v1
- targets[].enabled: explicit true required to inspect; missing/false means SKIPPED with no source/reports read.
- targets[].group: group id, for a fleet-wide summary.
- targets[].repo, from_tag, to_tag: read-only local Git source only; exact Git commit ids included in report, remote publisher not authenticated.
- required_evidence[]: explicit user-defined CI, scanner, health, migration, backup or rollback check; source_tool is a *label*, not evidence the named tool actually ran. Check status is an untrusted user assertion.
- Each claimed check PASS must include (a) the exact candidate Git commit sha, and (b) a local artifact with an independently computed SHA-256 value. CLI checks both links and the file bytes; this establishes limited provenance/binding, **not** truth or freshness of scanner output.
- Missing evidence or missing commit binding -> UNKNOWN. Mismatched release commit, mismatched receipt hash, or declared required check FAILED -> BLOCKED. Matching declared PASS still only REVIEW, never READY.
- Always no auto patch/merge/deploy/send/provider write. No telemetry, accounts, network calls, external tool invocation, or Docker socket.

Input limits: a regular (not symlink) manifest up to 512 KiB; up to 32 targets and 24 required checks per target; each artifact must be a regular (not symlink) file up to 1 MiB. JSON with unrecognized fields is rejected. The CLI never outputs artifact contents or absolute private repository paths, but it may report Git filenames and check IDs: treat reports from internal repos as sensitive.

Watch-plan exit semantics:
- 0: all watched targets need REVIEW only (and at least one watched target); **NOT** permission to upgrade.
- 2: one or more watched targets BLOCKED by source conflict, declared failed check or tampered artifact.
- 3: UNKNOWN evidence or no watched targets and no hard block.
- 1: invalid input or CLI failure.
Priority: BLOCKED > UNKNOWN > REVIEW. Skipped targets never influence these gates.

Known trust limitations:
- Checking SHA-256 against a digest supplied by the same operator does not authenticate the CI/OSV/Trivy author or confirm the tool ran. Signed immutable attestations, source identity, timestamps and true external scanner adapters are future gates.
- Exact local Git commit identity is not proof of remote repository publisher authenticity or deployed running version. No live upgrades, production data or restored backups were touched.
- A list of user-declared required checks is not complete runtime coverage. Even all declared checks passing is not a production-safe verdict.
- The CLI does **not** yet ingest native raw Renovate, OSV-Scanner or Trivy JSON; an operator must normalize status, source reference and hash into the watch-plan. This is an input contract, not a completed API connector.

## Acceptance demonstration

- Existing Rust R3 baseline before change: 36 targeted unit and CLI/Git tests, on Fedora Rust 1.100.0.
- New R5 offline tests use disposable synthetic local Git repositories, genuine SHA-256 artifact files and intentionally disabled watchers. Test passing artifacts, non-executed scanner, failed check, missing proof, wrong release commit, changed receipt, symlink artifact and symlink manifest; all remain no-send/no-deploy.
- Final R5 Rust regression: **24 library unit tests + 6 existing CLI tests + 10 Git integration tests + 10 watch-plan CLI integration tests = 50/50 PASS** on owner Fedora Rust 1.100.0. Rustfmt and strict Clippy PASS.
- A local real public OpenSEO v0.1.27 → v0.1.31 tag-pair demo traversed **514 Git paths** and used 3 deliberately different **synthetic/unexecuted** evidence states: required checks NOT_RUN → UNKNOWN (exit 3); one synthetic, byte-pinned same-commit artifact marked PASS → REVIEW (exit 0); the same bytes bound to the wrong commit → BLOCKED (exit 2). All three reported production_ready=false and performed_remote_queries=false. No real scanner execution was implied; no current live Tredven runtime was contacted.
- Watchlist default opt-out demonstrated: both sample targets SKIPPED, zero source reads, exit 3 (no watched targets).
- False-complete tests: a claimed PASS without an artifact, or without the correct candidate commit, is UNKNOWN rather than green. Symlink artifacts/manifests and hash mismatch are rejected or gated.

## Next ROI gate

Before building a daemon, UI, notification system or paid maintenance feed:
1. With explicit owner permission and no production mutations, normalize **one real Tredven-owned existing CI/scanner artifact** for a source-pinned local upgrade, and verify the report actually changes an operator decision.
2. If that gives repeatable value, add an adapter for **one** incumbent machine-readable output (e.g. OSV-Scanner V2 JSON), including verified tool version/schema and release pin. Avoid claiming a general adapter ecosystem before real artifacts exist.
3. Commercial or X-first launch still requires user adoption and a same-budget-holder paid residual gap; GitHub stars and passing synthetic tests are insufficient.

Current evidence: narrow R5 technical slice executed and tested offline; integrated production E2E and commercial usefulness not established. Full-project functional percentage UNKNOWN (no reproducible denominator, delta UNKNOWN); integrated E2E UNKNOWN (no real stack upgrade, delta UNKNOWN); production readiness UNKNOWN (no release approval/deploy, delta UNKNOWN).
