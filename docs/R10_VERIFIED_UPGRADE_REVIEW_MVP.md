# R10 — Verified Upgrade Review MVP (Rust core)

Date: 2026-11-22. Parent: R9 commit d274a4d96dcc73534ee3e889ee7653edd6846e35.
Branch: feat/verified-upgrade-review-r10-20261122.
Scope: public MIT Rust CLI ONLY; no private Tredven runtime, no production, no merge, no release, no GitHub Actions runs.

## 1. User-facing ability

One command combines local Git release tags, either two already existing scanner JSON files or two direct OSV-Scanner source scans, scanner findings, baseline/candidate delta, optional signed-file provenance and a conservative decision:

~~~bash
cargo run --locked -- review-upgrade \
  --config /path/to/operator-config.json \
  --evidence-dir /path/to/NEW-PRIVATE-RECEIPTS \
  --format markdown
~~~

An existing-reports example is at ../examples/r10-existing-reports.example.json. It is **read-only and network-free** by default. Existing reports with missing signed provenance remain UNKNOWN if non-blocking and BLOCKED if a confirmed severe candidate finding exists.

The local-osv-lockfile mode example is at ../examples/r10-local-osv-lockfile.example.json. It reads exactly two Cargo.lock snapshots from local Git commits, without checkout or hooks, in a private temporary directory. The owner explicitly opts in to executing a SHA-256-pinned OSV-Scanner executable and to public OSV API requests by changing the network permission field to true. **Never scan private lockfiles with public API access without deliberate authorization.** This mode runs the scanner twice (once per version), with all-packages, no-resolve, and no call analysis, and observes actual exit statuses. It does not execute Cargo, tests, Git hooks or code in either source repository.

The optional evidence directory is created with private 0700 permissions, files 0600, no overwriting: baseline.Cargo.lock, candidate.Cargo.lock, baseline.scanner.json, candidate.scanner.json, review.json and SHA256SUMS. The two Cargo.lock files exist only in direct local-scan mode. Check the receipt with sha256sum -c SHA256SUMS. **SHA256SUMS establishes file integrity only, not a signature or authenticated provenance**. Input files may contain sensitive paths or package metadata: do not upload them publicly.

Every R10 report has source_remote_publisher_attested=false, scanner_execution_cryptographically_attested=false, production_ready=false, release_authorized=false and action_authorized=false. A local scan is a *locally observed action*, not a signed CI run.

## 2. Actual public OSV-Scanner end-to-end qualification

Reference repository: https://github.com/attested-delivery/rust-template

- Baseline: official release tag v0.1.0, local Git commit 2b97f20f71e2b6d9c3f23ea7e968b7dd26d97e6a.
- Candidate: local-only (unofficial/unsigned) tag r10-local-main-snapshot, referencing public origin/main commit 44d052afce639390846b9369be3d4ea684f4e7c4. **Not an official upstream release.**
- Actual official GitHub-released OSV-Scanner v2.7.1 Linux AMD64, asset SHA256 fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8 (checked against official release metadata). This digest is not itself independent Sigstore publisher attestation.
- Baseline: 81 packages, one advisory (RUSTSEC-2026-0486), scanner exit 1 (vulnerability found).
- Candidate: 97 packages, the same one advisory (RUSTSEC-2026-0486), scanner exit 1.
- Rust E2E: two real OSV scans, 0 NEW, 0 RESOLVED, **1 PERSISTENT**, comparable scope true, delta diagnostic REVIEW but absolute candidate result and final report **BLOCKED**, exit 2. A persistent vulnerability is not a safe upgrade.
- The six-file private evidence receipt at local ignored output/r10-public-osv-real/r10-genuine-osv-evidence-v1 has passed sha256sum -c for all five payloads. The source repo and Rust repo were not modified by scanning (the Rust source changes described here are deliberate development changes).
- Actual OSV 2.7.1 output with all-packages omits vulnerabilities arrays for clean packages. Earlier synthetic R6/R7 assumed explicit empty arrays. That caused UNKNOWN delta on genuine scanner JSON, so R10 fixed the scanner parser and delta parser: **absent per-package vulnerabilities means no REPORTED advisories for that enumerated package**, not proof of scan execution. Wrong type, empty results, zero packages, bad source identity and missing coverage still fail closed. A separate real E2E verified the corrected behavior.

This proves a genuinely runnable public Git-source-to-scanner-to-report vertical, **not a production-safe or cryptographically signed scanner-run E2E**.

## 3. Actual signature and version security gates

The installed Fedora GitHub CLI is 2.97.0. GitHub's 2026 security advisories GHSA-wjmr-j3rp-mh2g and GHSA-4mq3-hpgx-9cx8 say the attestation signer-workflow and source-ref verification bugs were fixed in **GH CLI 2.102.0**. R10 requires at least 2.102.0 before invoking gh attestation verify. Missing, malformed, old or prerelease version outputs block, not silently fall back.

An official gh 2.105.0 Linux binary was staged in a separate owner-controlled toolchain directory with asset SHA-256 79e7ab5db738c48777b696e374f8b428f0647debfb424f44d2f426370407fe2f confirmed from GitHub release metadata. No sudo, root, global tool replacement or execution on private Tredven systems occurred.

On the same genuine third-party signed release artifact:
- System gh 2.97.0: **BLOCKED**, GH_ATTESTATION_VERIFIER_VERSION_NOT_QUALIFIED.
- Owner-isolated gh 2.105.0: **VERIFIED** with the exact R9 repo-ID, signing workflow, release tag, Git commit, SLSA predicate and offline trust-root bundle.
- R10 existing-reports mode with the genuine, signed public **binary** as both reports: both signed file origins VERIFIED, yet their content is not a scanner JSON. Scanner and upgrade verdict remain **UNKNOWN**, not falsely REVIEW.

An authenticated file is NOT proof that Trivy/OSV executed, that the DB was fresh, that scanned dependencies match the signed source, or that deployed software works. The unsigned local R8/R9 Rust release candidate remains unsigned.

Primary sources:
- https://github.com/cli/cli/security/advisories/GHSA-wjmr-j3rp-mh2g
- https://github.com/cli/cli/security/advisories/GHSA-4mq3-hpgx-9cx8
- https://cli.github.com/manual/gh_attestation_verify
- https://google.github.io/osv-scanner/output/
- https://github.com/google/osv-scanner/releases/tag/v2.7.1

## 4. ROI challenger, not merely tests

1. Reimplement a new Chainloop, Renovate, CI, generic policy engine or DSSE crypto: rejected, mature upstream OSS exists and business adoption is unproved.
2. Add more source-specific SQL/scanner rules: rejected, low marginal value and no unified user journey.
3. Ship a public release before source→scan→report path works: rejected, creates distribution friction without proven behavior.
4. **Selected:** one Rust command combining two local Git commits, an upstream scanner execution or imported reports, optional signed file verification, risk delta, absolute blocker precedence, and a reproducible owner-private evidence receipt. Reusing existing GitHub CLI and OSV binaries avoids duplicate engines.
5. Full independently signed scanner-execution provenance: still blocked without **an actual signed scanner report plus trustworthy signed workflow invocation record**. Do not fabricate a signed report or trigger GitHub Actions without separate permission.

R10 exit codes: 2 BLOCKED (including persistent candidate risk and invalid signing claim); 3 UNKNOWN (missing/unverified evidence without a known blocker); 0 REVIEW (local bounded review, NEVER deployment authorization); 1 configuration/invocation errors. The OSV executable itself is owner-selected and must be independently trusted; same-party hash + executable alone does not prove its upstream publisher.

## 5. Qualification and remaining gap

Proven: source Git refs and lockfile bytes, actual OSV scanner process return codes and bounded JSON, exact reported source path, native OSV missing-array shape, Git/source delta, old-gh fail closed, new-gh actual signature verification, real signed binary/non-scanner distinction, private checksummed evidence. Additional synthetic Rust tests cover missing provenance, invalid scan binary hash, absent explicit network approval, wrong signing commit, file-permission safety and no-overwrite.

Not proven: signed scanner *execution*, signed scanned-source claim, remote Git publisher authenticity of the local tag pair, real production rollback, hosted SaaS use, buyer ROI or production-ready release. No private Tredven tests, Actions run, merge or deployment.

## 6. Final local executable and test acceptance

- Full Rust workspace: **142/142 PASS** across 58 library, 15 authentic-attestation CLI, 6 legacy CLI, 10 Git CLI, 10 delta CLI, 27 plan CLI, 9 R10 review CLI, and 7 scanner CLI tests. The R9 public signed fixture and R10 real OSV public-source test were explicitly enabled during this test execution; this is *not* merely a mock-only pass.
- cargo fmt --check: PASS. cargo clippy --locked --all-targets -- -D warnings: PASS. No new crates were added.
- Real R10 private-source-independent public reference: verified 6 locally held files (five payloads and SHA256SUMS), 81 versus 97 real packages, 1 persistent advisory, BLOCKED. The owner's installed vulnerable gh is rejected; isolated fixed gh verifies an actual signed public artifact; the same signed non-scanner file remains UNKNOWN.
- Published main, previous R9 branch and private Tredven application unchanged. All scanner raw output and third-party signed assets remain in locally ignored directories and are intentionally *not* committed.

**R10 public-reference source→OSV→report vertical COMPLETED. Whole verification chain PARTIAL. Full OSS product PARTIAL. Functional readiness UNKNOWN (Δ UNKNOWN; no complete-feature denominator), integrated E2E readiness UNKNOWN (Δ UNKNOWN; real local source/scan E2E exists but independently signed run proof is missing), production readiness UNKNOWN (Δ UNKNOWN; no approved signed release or operating verification).**

Next highest ROI: obtain a genuinely signed **OSV/Trivy CI report with signed invocation-to-commit evidence** under an owner-authorized public workflow, or qualify an existing public signed scanner-run fixture, then reuse the present R10 GH verifier. Do not start another framework. User explicitly postponed private Tredven self-use tests.
