# R11 — Signed CI Upgrade Review and Independent Usability Gate

Date: 2026-11-22.
Branch: feat/signed-ci-upgrade-review-r11-20261122.
Parent: R10 a1878d35a2b09ca36dcb39d136cf5ce86c1fe3cf.

Scope: independent public MIT Rust CLI. No private Tredven application, no customer data, no GitHub Actions run, no signed scanner-report publication, no merge, no release or deployment.

## 1. New user capability

The existing Rust review-upgrade command supports an additional input mode: signed-ci-receipt. It reads an operator-maintained JSON config with:
- A local Git source repo and two pinned Git tags and resolved commit objects.
- Both original scanner JSON files and a CI-scan receipt claiming their SHA256 digests.
- The original lockfile SHA256 for both scanned Git source commits.
- OSV Scanner binary name, version, SHA256 and exact invocation arguments, plus exit code 0 (no findings) or 1 (findings) for both scans.
- A strict independent GH/Sigstore signer policy: signing repository name AND immutable ID, signing workflow path, source Git ref, exact signer commit, a genuine signed artifact subject filename/digest and a verified Actions run URI with run ID and attempt.

The CI signer's Git SHA is *not the same identity* as the two separately scanned third-party source SHAs. The Rust reader verifies this distinction and never accepts a claimed signer commit as a substitute for the scanned source.

Example operator configuration: ../examples/r11-signed-ci-receipt.example.json (intentionally invalid source paths and zero signer commit, so never silently live).

Command after independently obtaining a genuine signed CI receipt and official, trusted bundle/root files:

    tredven-upstream review-upgrade \
      --config /path/to/OWNER-REVIEWED-CONFIG.json \
      --format markdown \
      --evidence-dir /path/to/NEW-private-receipts

The optional evidence directory contains original scanner JSON files, original source lockfiles from the local repository, exact receipt bytes, a structured decision report and a SHA256SUMS file. Files are private, no overwrite. Checksums are integrity markers, NOT signatures.

For unsigned or fake signed source-bound receipts, the decision is BLOCKED. A clean signed CI receipt can produce only diagnostic REVIEW, never a release approval. If the signed receipt contains source or scanner evidence contradictions, the verdict is BLOCKED. Missing or incomplete scanner coverage is UNKNOWN when the upstream evidence gate has otherwise passed. No production grants are ever created.

## 2. Manual-only CI reference — prepared, not executed

The file ../.github/workflows/r11-manual-public-osv-attest.yml is a public-only, owner-gated workflow with exactly one trigger: workflow_dispatch. No push, PR or schedule triggers. It was NOT launched or approved to run in this R11 development scope.

The workflow is intended to:
1. Run on GitHub-hosted Ubuntu 24.04, with only the contents read, id-token write, attestations write GitHub permissions.
2. Check out the signer source without saved Git credentials using a pinned official actions/checkout commit.
3. Fetch two fixed public commits in attested-delivery/rust-template, with an official baseline release tag and a local-only, unofficial snapshot tag. It does not execute third-party source code.
4. Download official OSV-Scanner 2.7.1 and verify its pinned published SHA256 before execution.
5. Use existing Rust R10 review-upgrade to extract both Cargo.lock Git objects, perform two real public OSV API scans, check results and save original SHA256-bound evidence.
6. Produce an *unsigned* run claim via scripts/ci_scan_receipt.py, checking the exact GitHub CI environment context and evidence file/source hashes.
7. Delegate cryptographic attestation creation to upstream actions/attest-build-provenance and optionally upload ONLY the public-reference artifacts for consumers.

No secret is used, and running the workflow would disclose only public dependency metadata. Triggering it would publish an external attestation and consume public GitHub Actions resources; those acts require separate owner approval. Workflow source on a feature branch also cannot substitute for a review and authorization of a canonical default-branch workflow.

The signed SLSA receipt is a workflow assertion, not an independently observed record that each scanner subprocess really ran. The owner needs to audit the exact pinned workflow revision and the public run. scanner_execution_cryptographically_attested remains false, even if a genuine signed receipt passes content and origin verification, until independent invocation evidence is qualified. This is an intentionally conservative meaning.

## 3. Genuine evidence actually obtained

Public reference: https://github.com/attested-delivery/rust-template

- Official baseline tag v0.1.0: commit 2b97f20f71e2b6d9c3f23ea7e968b7dd26d97e6a.
- Candidate is a locally created unofficial, unsigned r11-local-main-snapshot tag at publicly fetched commit 44d052afce639390846b9369be3d4ea684f4e7c4.
- Actual Google OSV-Scanner 2.7.1 binary, SHA256 fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8, obtained from official public release and hash checked.
- Baseline: 81 packages; candidate: 97 packages. The original RUSTSEC-2026-0486 vulnerability persists. Both scans completed with exit 1. The Rust E2E report says 0 new, 1 persistent and BLOCKED.
- Locally saved evidence passed SHA256SUMS readback for two original lockfiles, two native scanner JSON files and the overall review report.
- A locally generated CI receipt using **synthetic GitHub environment variables** bound the real public source/report bytes. The Rust signed-ci-receipt evaluator correctly reported source_commit_and_artifact_hashes_bound=true but signed_run_receipt_accepted=false and BLOCKED because it had NO matching genuine cryptographic signature.
- R9's unrelated genuine GitHub-signed release binary still passes official GH signature verification on patched gh 2.105.0. Its signed SLSA statement and certificate contain a matching exact GitHub Actions run ID and attempt URI; R11 now exposes and checks that identity, but that binary is NOT a signed scanner report.

The public OSV evidence under locally ignored output/r11-public-reference-local was NOT uploaded. No GitHub CI was run, no real signed scanner receipt was produced. Hosted signed scanner E2E = **NOT PROVEN**.

## 4. Reproducible qualification

Rust regression covers: valid-shape unsigned source-bound receipt BLOCKED; changed scanner JSON SHA BLOCKED; wrong original Git source commit or locked Cargo.lock SHA BLOCKED; wrong signer SHA or run ID BLOCKED; falsified OSV process exit BLOCKED; absent trusted root BLOCKED with no online fallback; malformed receipt invalid; private no-overwrite evidence bundle preserving all original bytes; static manual-only workflow event scope.

scripts/test_ci_scan_receipt.py contains synthetic environment and real public file hash checks, rejecting forged source, altered scan/lockfile bytes, wrong repo ID, missing GitHub run context and false scan status. These tests do NOT fabricate signatures or count simulated GitHub CI as verified execution.

**Executed verification on the owner Fedora machine (with the real, public fixtures explicitly enabled):**

- Rustfmt check PASS; strict cargo clippy --locked --all-targets -- -D warnings PASS.
- **156/156 Rust tests PASS**, including 15 real GitHub attestation CLI tests, 11 R11 signed-ci-receipt CLI regression tests, 9 R10 public OSS review tests, and the original R1-R9 regressions. The R9 genuine signed release sample and R10 actual public scanner network fixture were enabled; this number is NOT a CI signed scanner receipt E2E measurement.
- **9/9** Python CI receipt generator tests PASS, using actual public native OSV outputs and a **synthetic local GitHub environment**, with no signature or hosted CI.
- **13/13** Python R8 local release-candidate integrity regressions PASS, including tampered file and symlink denial.
- Manually verified the GitHub workflow YAML is valid and has **only workflow_dispatch**, permissions are restricted, and all external official actions are pinned by exact commit SHA; manual Actions run **NOT EXECUTED**.
- A 62-file Cargo source package was successfully built and validated OFFLINE, with no new Cargo dependency. From its extracted source, cargo install --offline --locked built the CLI in a **fresh target directory** and installed it into a separate, owner-controlled root on the same Fedora host.
- The newly installed executable itself independently verified the genuine R9 signed release, including the exact signed Actions run URI (**VERIFIED**), and correctly rejected the genuine-public-source but **unsigned** R11 scan receipt (**BLOCKED**, exit 2). No downloaded untrusted third-party binary was executed during that signed binary verification.
- This proves **same-host isolated-source installation**, not cross-Linux, hosted Actions, signed scanner-run or production readiness. After the final commit, the original clean-source local unsigned release candidate is still subject to a final no-publish check.

No hidden PASS from unspecified fixtures is considered production qualification.

Evidence levels:
- Local real public Git/OSV scans: **executed**, public API queries, not signed.
- Real signed public third-party release binary: **cryptographically VERIFIED**, not a scanner artifact.
- Rehearsal receipt: **synthetic unsigned provenance**, fail-closed BLOCKED.
- New manual GitHub Actions workflow: **static/source only; NOT RUN**.
- Actual signed CI scanner-run end-to-end: **UNKNOWN / NOT PROVEN**.
- Private Tredven E2E: **NOT RUN**, per user request.
- Production release: **NOT QUALIFIED**.

## 5. Mandatory ROI challenger

Alternatives considered:
A. Build new cryptography, scanner, CI controller or Chainloop-style service. Rejected: high complexity, mature existing upstream software, unproven marginal customer value.
B. Publish unsigned R10 now. Rejected: it would simplify installation but leave the actual signed scanner-origin decision path unresolved.
C. Continue piecemeal parser additions. Rejected: already integrated R10 real OSV report exists, low incremental user value.
D. Selected: compose the existing R10 scanner+Git path with an owner-gated upstream GitHub Actions attestation producer, exact signer+run+scanned-source hash binding in the Rust CLI, and an independent local installation gate.
E. If owner does not authorize a real GitHub Actions run, preserve the partial-but-safe result and do NOT forge a signed fixture or count a synthetic CI environment as a hosted E2E.

Upstream references (no imported third-party source implementation):
- https://github.com/actions/attest-build-provenance
- https://cli.github.com/manual/gh_attestation_verify
- https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations
- https://google.github.io/osv-scanner/output/
- https://github.com/google/osv-scanner-action/blob/main/.github/workflows/osv-scanner-reusable-pr.yml
- https://github.com/chainloop-dev/chainloop

No new Rust dependency, production mutation or customer-provider integration was necessary.

## 6. Full project readiness and next gate

R11 signed-CI integration code and local executable acceptance: subject to final clean source, tests and packaging evidence.
Owner-authorized hosted signed scanner execution: BLOCKED (not authorized).
Whole public Rust OSS product: PARTIAL.

Functional readiness UNKNOWN (Delta UNKNOWN; no reproducible whole-roadmap denominator).
Integrated E2E readiness UNKNOWN (Delta UNKNOWN; the genuine CI signature-to-scanner execution vertical remains untested).
Production readiness UNKNOWN (Delta UNKNOWN; no owner-approved signed release, customer runtime or deployment).
Commercial user value and external adoption: NOT PROVEN.

Next high-ROI owner action when appropriate: review and explicitly authorize one *public-only* manual workflow on the canonical GitHub branch and its first signed CI run. After owner authorization, the existing R11 Rust CLI can verify the resulting real signed scan-run receipt, exact GH Actions invocation and source/report bytes. No more homemade cryptography or wide adapter research needed.
