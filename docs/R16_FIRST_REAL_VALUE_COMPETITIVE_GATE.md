# R16 — First Real User Value & Competitive E2E Gate

Date: 2026-11-22. Scope: **public Rust dependency-upgrade decision**, not release authorization.
Research branch: `research/r16-fd-real-value-benchmark-20261122` (local only). Parent: R15 `5ad21855d9bbbfcb33625ca6d5af37017c22a26d`.
**Verdict: LOCAL PUBLIC-DATA E2E PASS; CUSTOMER VALUE UNPROVEN; NO-GO FOR MORE SCANNER/ATTESTATION FRAMEWORK DEVELOPMENT.**

## Reproducible independent source

- Repository: https://github.com/sharkdp/fd — independent of the earlier `attested-delivery/rust-template` qualification fixture.
- Baseline tag `v10.4.2` -> commit `7027d45303b412be6fa9c09d689cc6276748fb38`.
- Candidate tag `v10.5.2` -> commit `b2a287b3993768e0ec52f0852916917f23fb2a38`.
- Both commits and root Cargo.lock files obtained by public shallow no-checkout Git and compared to GitHub's tag refs. `git diff`: 41 changed paths.
- Baseline Cargo.lock SHA-256 `8a3bac0e2c4583e8839ed0009341cfb1eb98121ecbeb595c750099c81e1699a6`; candidate `080f85e31279c422c5591ad7092ef93c7171711122c7de2b7aa32b84c5e72ed9`.
- Actual lockfile package records: 126 -> 95. Only the **root Cargo.lock** was scanned. No nested manifests, application runtime tests, build, private package sources, licence compatibility, downstream users or remote publisher attestation.
- Scanner: official OSV-Scanner v2.7.1 pinned binary SHA-256 `fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8`, resolved on the Fedora test host. The 56 MB scanner and 1.5 MB local Rust CLI were isolated under ignored `output/r16-fd-independent-benchmark/`.

## Actual comparison, not a synthetic fixture

| Measurement | Direct OSV-Scanner v2.7.1 | Tredven Upstream original | Tredven Upstream with R16 fix |
| --- | --- | --- | --- |
| Baseline findings / process exit | 3 / 1 | 3 / 1 | 3 / 1 |
| Candidate findings / process exit | 0 / 0 | 0 / 0 | 0 / 0 |
| Resolved advisories | Manual comparison required | 3 computed | 3 computed |
| Aggregated decision | Not produced by individual scans | REVIEW | REVIEW |
| Exact Git source/lock SHA and changes | Separate Git procedure required | Bundled in report | Bundled in report |
| `expected_subject_matched` | Not a Tredven field | FALSE (bug) | TRUE / TRUE |
| Production release authorization | None from scanning | False | False |
| Measured wall time (one run) | 1.190 + 0.558 = 1.748 s | 2.458 s | 1.653 s |

**Timing limit:** timings were single runs on different cache and network states. Neither a speed advantage nor a statistically significant regression is established. All figures EXCLUDE clean-machine Rust/OSV installation and human configuration. An independent cached Rust `cargo build --release` was measured at 9.36 s, and public shallow Git clone at 0.95 s; these are host-specific, not representative first-user onboarding times.

Three previously reported RUSTSEC advisory IDs and lockfile package version changes:

| Crate | Baseline | Candidate | Advisory absent in candidate OSV output |
| --- | --- | --- | --- |
| `anyhow` | 1.0.102 | 1.0.104 | RUSTSEC-2026-0190 |
| `crossbeam-epoch` | 0.9.18 | 0.9.21 | RUSTSEC-2026-0204 |
| `rustix` | 1.1.4 | 1.1.6 | RUSTSEC-2026-0486 |

This demonstrates three **resolved reported occurrences**, not a clean dependency universe, proof of exploitability remediation across the entire application, test compatibility or production readiness.

## Exact root cause found on real data

Both generated OSV JSON reports declared `results[0].source.path` equal to the same scanned temporary `Cargo.lock`, but the Tredven scanner summary stated `expected_subject_matched=false` for both. `src/scanner.rs::osv` tracked mismatched source paths but **never set the flag true** for valid paths. A focused synthetic regression asserting true for matching and false for wrong/missing sources **FAILED** before the change, then **PASSed** after it; the real public-data E2E independently confirmed both flags are now true.

Smallest fix: track a missing/unexamined source separately, then set the scope-match flag only if every inspected result has the exact expected source. A wrong path still **BLOCKS**, a missing path still yields **UNKNOWN** for clean results, and overlarge source lists remain unqualified. No new dependency or relaxation of `REVIEW`, `BLOCKED`, signature or release gates.

After rebuilding locally, the same actual `sharkdp/fd` E2E qualified both source paths (`true` / `true`), still recorded 3 -> 0 findings, `REVIEW`, `production_ready=false`, `release_authorized=false`, and `scanner_execution_cryptographically_attested=false`.

## User-facing friction / cold-start gap

- Local shell workflow required manually fetching two Git tags, obtaining a pinned OSV binary, acquiring/building Tredven Upstream, constructing a JSON configuration with source, tags, binary and SHA, then invoking `review-upgrade`.
- The **pre-fix** Tredven Markdown was **650 bytes / 17 lines** and omitted affected crate names and RUSTSEC IDs. **R16 fixed this observed usability blocker:** the verified **924-byte / 22-line** report includes all three affected crates and advisory IDs, retains `REVIEW` and explicitly denies deployment/release authority. Exact old/new crate versions remain in the Cargo.lock/raw data rather than the one-page output.
- GitHub currently exposes **zero public Tredven Upstream releases**, so independent self-serve install and true cold-start user validation have **NOT** been performed.
- Human decision time, number of user interventions, willingness to install/pay, perceived trust value and external user success are **UNKNOWN**, not zero.

## OSS comparison: evidence levels must remain separate

- **Native OSV-Scanner: ACTUALLY RUN** on the same two real lockfiles and matched 3 and 0 findings. Already offers broader language and lockfile support. https://google.github.io/osv-scanner/usage/scan-source
- **Mend Renovate: DOCS-ONLY, NOT RUN** on this case. Self-hosted `dryRun=lookup` can list dependencies and available updates without PR creation; hosted mode can automate update PRs. This is complementary; no equivalent timing or user-decision quality was measured. https://docs.renovatebot.com/self-hosted-configuration/
- **GitHub Dependabot / dependency review: DOCS-ONLY, NOT RUN** on this case. GitHub has security alert and dependency facilities, but their actual state and entitlement for `sharkdp/fd` were not qualified, and this project was not enrolled or modified. https://docs.github.com/en/rest/dependabot/alerts
- **Tredven: ACTUALLY RUN.** Adds one source-bound cross-version delta and a conservative decision gate. It did **not** discover an additional advisory beyond native OSV, nor independently attest source publisher or child scanner process execution. Existing OSS parts may reproduce the benefit; a differentiating user need has not been established.

## Acceptance, ROI challenger and decision

Acceptance evidence: one independent public source Git pair, two genuine OSV outputs, two real Tredven E2Es (before and after the fix), a falsified source-path flag, a corrected end-to-end report, full Rust and Python regressions with the existing genuine signed-public R9 binary fixture enabled.

- Rust tests: **159/159 PASS** under explicitly selected patched GitHub CLI 2.105.0. Python receipt tests: **10/10 PASS**. `cargo fmt --check`, Clippy `--offline --locked --all-targets -- -D warnings`: PASS.
- An earlier R16 test attempt failed **5 R9 tests** because the host PATH selected an older system `gh` binary. Exact root cause was the verifier version gate (`GH_ATTESTATION_VERIFIER_VERSION_NOT_QUALIFIED`); correcting PATH to the already pinned `gh 2.105.0` restored **159/159 PASS**. No application patch to bypass the verifier was made.
- The R16 scope bug was fixed with a red/green test and public-data E2E retest. A second directly observed usability repair reuses existing parsed findings to expose a bounded `resolved_sample` in the JSON delta and to list new/resolved IDs in Markdown. No extra scanner, cryptography, orchestration or GitHub mutation. The JSON delta gains an additive field within v1; strict external consumer compatibility is **UNKNOWN**.

Options considered: (A) continue more CI/attestation/OSS-adapter development; (B) immediately merge and publish without user-value evidence; (C) verify a real independent upgrade and correct only a falsified critical report invariant; (D) consolidate into upstream OSV/Renovate or stop if differentiation cannot be shown. **Selected C now, including a minimal user-report usefulness repair; D remains the default if a controlled user test yields no distinct decision benefit.**

**Recommended next highest-ROI slice:** have a real independent developer try the corrected 924-byte decision summary on a disposable public Git repository, comparing it to two OSV scans. For an external trial, first prepare a safely installable archive incorporating separately developed R12 license notices. Outside contact, merge and release require separate owner approval. Do not substitute internal/synthetic feedback for genuine user evidence.

**Overall project status: PARTIAL.** Functional readiness **UNKNOWN** (Delta UNKNOWN; no reproducible whole-product denominator); integrated E2E **UNKNOWN** (Delta UNKNOWN; this one real *local public-data* vertical passed but hosted signed scanner workflow did not run); production readiness **UNKNOWN** (Delta UNKNOWN; no owner-approved signed release, customer run, user-value or commercial validation). Repo PR #1 remains Draft and unmerged. R16 branch is local and is **not pushed or merged**.

## Evidence storage / reproducibility notes

Raw results and pinned snapshots remain local only in ignored `output/r16-fd-independent-benchmark/`: `r16-tredven-config.json`, `tredven-evidence/review.json`, `tredven-fixed-result.json`, `tredven-evidence-fixed/review.json`, `osv-native/{v10.4.2,v10.5.2}/stdout-osv.json`, `osv-native-execution.json`, `r16-human-readable.md` (original), `r16-human-readable-actionable.md` (corrected), and timing files. Not GitHub-published evidence.

Reproduction requires (1) a fresh public Git clone without executing source code; (2) both specified tags and exact SHAs, plus the pinned v2.7.1 scanner; (3) a manually created JSON config matching `schema=tredven.upstream.upgrade-review.v1` with `local-osv-lockfile`; (4) `tredven-upstream review-upgrade --config ... --evidence-dir NEW_DIR`. The command issues **public OSV API** requests and deliberately does not fetch private sources or grant deployment authority.