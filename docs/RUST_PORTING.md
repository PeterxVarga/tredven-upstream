# Porting the existing upgrade gate to Rust

This is a **new public core**, not a publication of the private internal integration and approval infrastructure.

## Read-only legacy baseline (private, not included)

Internal reference at the time the new public core was started:

- The original implementation is in a separate private workspace; **do not copy source pins, private receipts, tenant bindings or operational launchers here**.
- Python gate: 408 lines of source/adapter compatibility and patch safety evidence integration.
- Python tests: 21/21 targeted offline regressions **observed on the internal Fedora checkout** before the new port.
- Existing connected-provider contracts and historical patch/database evidence remain private and are not part of the new public CLI.

## Rust Anything reuse decision

[erkamyaman/rust-anything](https://github.com/erkamyaman/rust-anything) (MIT) is a relevant **optional migration verification tool**, not a dependency of this CLI.

- Its useful mechanism: **record original behavior, port one bounded unit, compare cases, gate the replacement**.
- It does **not** translate or implement Rust by itself. AI or a developer must write that code.
- **Never run `rust-anything record`, `app record`, `diff` or `app replay` on an owner-private runtime without an isolated source copy and an entirely synthetic, credential-free environment.** Recording can replay file/network/DB effects many times.
- No `rust-anything` binary or MCP server is required to build or test this public repository. We are not claiming its `gate` has passed.

## Baseline scope and honest parity level

First migrated concepts: deterministic source identity comparison, changed-path categories, evidence-state precedence, JSON/Markdown reporting, always-denied authority, and now **read-only local Git tag/commit/diff inspection**. This is not a byte-for-byte port of the 408-line Python tool: official remote provenance verification, hosted/provider adapters, legacy receipt verification and runtime tests have **not** been ported.

The unit/CLI suite now includes disposable local Git repositories with genuine commits, tags and changed paths. A separate read-only evaluation of the **public OpenSEO** v0.1.27→v0.1.31 Git objects observed 514 changed paths with rename detection disabled, and a **private local** comparison matched the original Python classifier on all 514. This is classifier parity only; no original private code, receipts, customer settings or whole-adapter identity was published. See [R2 public source qualification](R2_SOURCE_QUALIFICATION.md).

## Staged E2E milestones

1. **COMPLETE (local):** compile a stand-alone Rust binary, deterministic synthetic JSON/Markdown output, fail-closed status, error codes, tests and local formatting/lint checks.
2. **PARTIAL (local-only):** `inspect-git` verifies named local Git tags, dereferences the exact commit objects and compares changed paths without changing source or fetching data. **NEXT:** verify the upstream publisher and the intended release refs through an explicitly bounded, authenticated or public read-only source path, with honest truncated/unavailable evidence semantics. Do not infer that a local tag proves remote publisher identity.
3. **PARTIAL (one exact release):** `inspect-contract` has a strictly pinned OpenSEO v0.1.31 foreign-key-parent schema preflight, checked against Git object blobs and synthetic negative fixtures, with no SQL execution. A **general** declarative extension protocol and actual application smoke tests remain unimplemented. No arbitrary downloaded executable rules.
4. Demonstrate two real public upgrade pairs with a meaningful gap not already handled by Renovate or an application's native migration report.
5. Only separately and explicitly authorized: public v0.x release, opt-in X communication, and actual budget-holder tests for managed verified intelligence infrastructure.

## Stop conditions

Missing verified source, partial diff, unavailable local runtime, untested rollback, corrupt provenance or a newly moved upstream target is **never** interpreted as safe production readiness.

Do not create a second production authority or import Tredven customer data into public test fixtures. Never treat Rust build success, GitHub stars or social reach as paid-user validation.

## R3 source contract proof

A narrow Rust OpenSEO v0.1.31 Stripe Projects 0049 rule detects whether two foreign-key parent columns match the pinned baseline Drizzle source schema; it blocks synthetic malformed inputs. This is not whole adapter equivalence or a real database migration. See [R3 qualification](R3_OPEN_SEO_STRIPE_CONTRACT.md).

## R5 OSS workflow reuse

An opt-in, local-only multi-target watch plan now combines exact Git tag changes with user-declared, byte-bound CI, scanner and rollback receipts. This is an adapter *input contract*, not a scanner integration or proof of release safety. See [R5 adoption analysis](R5_OSS_WORKFLOW_ADOPTION.md).

## R6 native security scanner formats

The Rust core now recognizes **Trivy JSON v2** and **OSV-Scanner v2 JSON** as local read-only evidence, in both `inspect-scan` and source-tag-bound `inspect-upgrade` plus multi-target `inspect-plan`. It conservatively interprets output and never runs the original scanner or claims an authenticated producer. This replaces manual PASS/FAIL normalization for those JSON cases, not the original native tools or whole private adapters. See [R6 development and proof](R6_NATIVE_SCANNER_EVIDENCE.md).

## R7 source-aware scanner delta

The independent Rust CLI now offers `inspect-delta` and `inspect-upgrade-delta`, comparing two Trivy/OSV-Scanner JSON artifacts while enforcing exact scan scope, stable finding identity, optional source-tag commit binding and a conservative *absolute candidate* verdict. It does not replace `osv-scanner-action` baseline reporting or scanner security databases. [Details, ROI counterfactual and test evidence](R7_SCANNER_UPGRADE_DELTA.md).

## R9 delegated signed artifact provenance

The Rust CLI now accepts a strict, reusable owner-maintained GitHub attestation identity policy and delegates *all* cryptographic verification to installed official `gh`. Signed provenance is checked offline with bundle/root by default, or using explicit online public read-only GitHub lookups. An independent **real signed release binary** was verified; no signed scanner JSON has yet been tested. See [R9 proof and trust limitations](R9_REAL_GITHUB_ATTESTATION.md).
