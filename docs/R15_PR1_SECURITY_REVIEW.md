# R15 — PR #1 Targeted Security and Integration Review

Date: 2026-11-22. Repository: `PeterxVarga/tredven-upstream`.
PR: https://github.com/PeterxVarga/tredven-upstream/pull/1
Review source: `feat/r14-manual-ci-owner-qualification-20261122`, initially
`824c51301bd7783e4e693df8e87d86962ab8729d`.
Base `main`: `42a749d9845dcfb4eb553760021e42c035b981c4`.
No merge, release, GitHub Actions dispatch, private scan or deployment.

## Outcome and review scope

**Targeted local review: PASS after one defensive fix. Hosted E2E: NOT PROVEN.**

The draft PR adds 54 files versus the still-bootstrap `main`, covering R2–R11
and R14. This round reviewed the critical signed-receipt route, the scanner
process invocation and source-bound evidence, manual workflow authority,
action pinning/output compatibility and local regressions. It is **not** an
exhaustive security audit of all 54 files or a production-ready endorsement.
R12 license-annex integration and R13 OSS research are separate local branches
and are **not included** in PR #1.

## Security and release boundaries observed

- GitHub confirms the PR is draft/open, no merge conflicts, the base and
  head commit identities, and **0 Actions runs** before this change.
- Manual reference workflow: sole trigger `workflow_dispatch`, default-branch
  `main` guard, immutable repository ID, GitHub-hosted `ubuntu-24.04`,
  `contents:read`, `attestations:write`, `id-token:write`; no PR, push or
  scheduled event.
- Pinned `actions/checkout`, `actions/attest-build-provenance` and
  `actions/upload-artifact` commit references were resolved upstream.
  The pinned provenance action's published `action.yml` declares the
  `bundle-path` output used by R14.
- Reference OSV v2.7.1 checksum and public source Git SHA pins stay intact.
  Two actual public reference scans previously produced findings (exit 1);
  these are completed scans, **not** clean scans or signed CI evidence.
- Rust delegates cryptographic verification to patched GitHub CLI 2.102.0+
  with explicit signer, repo ID, source SHA, signed artifact, trusted timestamp
  and workflow-run identity. `release_authorized`,
  `scanner_execution_cryptographically_attested` and `production_ready`
  remain false, including after a valid signature.

## Concrete mechanism and smallest fix

The R11 `src/attestation.rs` post-verification parser originally:
1. Allowed `verified_fields_match` to find a correctly matching certificate,
   timestamp, runner and artifact subject in **one** returned record.
2. Separately searched for `runInvocationURI` and matching SLSA
   `invocationId` in **any** returned record with only partial identity
   checks; it did not enforce the same exact signer/workflow/ref on that
   chosen record.

A synthetic two-record fixture with record A meeting the full policy but no
run URI, and record B with a mismatched signer and a plausible run URI,
reproduced this inconsistency: **red test FAILED** before fix (the wrong URI
was accepted). This demonstrates a parser cross-record binding error,
**not** a proven way of making official `gh` produce malicious successful
verification records.

The minimal safety repair extracts one `verified_record_matches` predicate
and reuses it both for the certificate/subject gate and for selecting the
run URI. The URI must now come from the **same** fully accepted record.
No new dependency, cryptography or trust root was introduced. Added a
synthetic negative test and an independent valid same-record positive test.

## Reproducible evidence

- Official upstream `rhysd/actionlint` v1.7.11 tarball SHA256 matched
  GitHub's release asset digest:
  `900919a84f2229bac68ca9cd4103ea297abc35e9689ebb842c6e34a3d1b01b0a`.
  It executed locally from ignored output and **PASS**ed the 8-step workflow.
  This is static validation, not hosted execution or publisher Sigstore
  verification.
- A focused adversarial Rust test initially **FAILED** before the fix, then
  passed. The paired positive test also passed.
- `cargo fmt --check`: PASS.
- `cargo clippy --offline --locked --all-targets -- -D warnings`: PASS.
- `cargo test --offline --locked --all-targets -q`: **158/158 PASS**,
  with the previously saved genuine, independently trusted *public R9
  signed-binary* fixture enabled and the R11 public scan fixture enabled.
  This is a genuine verification regression for an unrelated signed binary,
  **not** a signed scanner execution.
- `python3 -B -m unittest scripts/test_ci_scan_receipt.py -q`: 10/10 PASS,
  using the previously saved public R11 reports.
- `git diff --check`: PASS.

## Mandatory ROI challenger

Three materially different options were considered: (A) approve/merge the
currently draft PR without deeper scrutiny (owner gate, unjustified);
(B) implement a new Witness/Chainloop integration (large operational
footprint and R13 exit-1 mismatch); (C) validate the existing GitHub-native
path with actionlint and fix the observed post-crypto record-binding weakness.
**Selected C**, which closes a falsified trust-policy invariant at low cost,
without new infrastructure. No claims of customer adoption or measurable
business impact.

## Remaining gates / project readiness

- **Owner-only:** review/approve/merge the 54-file draft PR to `main`.
- **Separate owner-only authorization:** first manual `workflow_dispatch`
  after the canonical `main` workflow has been reviewed.
- **After hosted run:** independently verify the actual public scanner run's
  signed receipt, official Sigstore trusted root, exact invocation ID and
  originally scanned source/lock/report bytes. An attested workflow claim
  does not independently prove every child process execution.
- **Before any binary commercialization:** integrate/verify the separately
  developed R12 third-party license notices; PR #1 does not include them.

Status: **PARTIAL** for the full product. Functional readiness: **UNKNOWN**
(Δ UNKNOWN); integrated hosted E2E: **UNKNOWN** (Δ UNKNOWN); production
readiness: **UNKNOWN** (Δ UNKNOWN). No comprehensive, defensible, historical
project-wide denominator exists. Local R15 checks are narrower, reproducible
PASS evidence and must not be misrepresented as project readiness.
