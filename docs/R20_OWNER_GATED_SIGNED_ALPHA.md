# R20 — Owner-gated signed alpha build and external verification

**Date:** 2026-11-22. **State:** PR-DRAFT-READY / HOSTED-SIGNING-NOT-RUN / NO_PUBLIC_RELEASE. This is an implementation of the manual signed candidate path, not a completed public launch.

## Canonical source, value goal, and ROI challenger

- Repository: `PeterxVarga/tredven-upstream` (public). Upstream default branch: `main` commit `42a749d9845dcfb4eb553760021e42c035b981c4` at R20 start.
- Parent PR #1 (Draft, unmerged): `feat/r14-manual-ci-owner-qualification-20261122` commit `5ad21855d9bbbfcb33625ca6d5af37017c22a26d`.
- Parent PR #2 (Draft, stacked on #1, unmerged): `feat/r19-portable-alpha-review-20261122` commit `876df9375d61cf3d94e8597439f9ec0d2cea396c`.
- R19 baseline: verified unsigned static Linux x86-64 local alpha candidate with SHA256 `8dff3ed14fdb8e3e11eb6e7d9995596d70e37ee0befd943c6220f5072e48cf42`. It passed a real public Git+OSV scanner E2E, a Debian 12 offline runtime smoke, 171/171 Rust tests and 24/24 release/license tests.
- User capability target: after separately approved merges and an authorized manual GitHub run, a user can obtain a build produced on a GitHub-hosted runner, independently verify the *archive* hash, GitHub Sigstore signer identity and exact approved main source SHA, and safely run the read-only CLI on a public Rust Git checkout.
- Real obstacle: no Actions runs, signed alpha or public release exist yet, and `main` is not branch protected. Do not confuse completed local offline tests with hosted signatures.

## ROI choices and selection

1. Merge and publish immediately: fastest distribution, but lacks release signer source evidence and owner authorization. **Rejected pending approval.**
2. More adapters/billing/hosted dashboard: more features but no independent developer adoption proof. **Deferred.**
3. Reuse the already qualified R19 archive and GitHub's pinned official Sigstore attest action in a *manual-only*, owner-gated workflow; add a strict artifact+signer verification path. **Selected.**
4. Delay everything until third-party user exists: fails to resolve the trust/install barrier needed for that user. **Rejected.**

## Workflow: `.github/workflows/r20-manual-alpha-provenance.yml`

- The **only** trigger is `workflow_dispatch`. No `push`, `pull_request`, `release`, schedule or webhook triggers.
- Job checks original repository name **and numeric repository ID 1467524521**, `refs/heads/main`, `github.actor` and `github.triggering_actor` = `PeterxVarga`; it also verifies the checked-out commit equals `GITHUB_SHA`.
- Runner `ubuntu-24.04` (GitHub-hosted), `contents:read`, `id-token:write`, `attestations:write`, timeout 35 minutes; no checkout credentials persist.
- Action dependencies use exact pre-reviewed SHA pins for `actions/checkout`, `actions/attest-build-provenance`, and `actions/upload-artifact`.
- Installs pinned Rust 1.100.0 and its musl target, `cargo fetch --locked` in public network, then **offline** invokes the existing release candidate script `build --portable-musl` and the independent `verify` command.
- Checks candidate archive SHA256SUMS, manifest exact GitHub source SHA, `publication_authorized=false`, native static Rust CLI smoke against a checked-in synthetic input, and pinned third-party and runtime license notices.
- **Attests the exact `tredven-upstream-v0.1.0-x86_64-unknown-linux-musl.tar.gz` archive**, not a generic PR or scanner result, using the official GitHub/Sigstore provenance action. Preserves its output bundle for offline verification.
- Uploads **two short-retention (7 day) GitHub Actions artifacts**: `r20-alpha-candidate-bytes` (the four exact RC files) and `r20-alpha-attestation-bundle` (the attestation JSONL). This is **not** a GitHub Release, package publish, deployment or message.

## Independent consumer verification (only AFTER a real owner-approved signed run)

Use an installed, trusted **GitHub CLI 2.105.0 or newer**. The online mode requests the attestation from GitHub and avoids the offline-bundle repository-renaming limitation documented by GitHub. Replace `RUN_ID` with the actual completed workflow run ID, not a fabricated value.

```bash
gh run download RUN_ID -R PeterxVarga/tredven-upstream \
  --name r20-alpha-candidate-bytes --dir ./candidate
gh run download RUN_ID -R PeterxVarga/tredven-upstream \
  --name r20-alpha-attestation-bundle --dir ./signature

# Optional extra exact-byte release-candidate checks from a trusted source checkout:
python3 -I -B scripts/release_candidate.py verify --dir ./candidate

# Native GitHub CLI verifies the signed archive, signer WORKFLOW and source:
gh attestation verify ./candidate/tredven-upstream-v0.1.0-x86_64-unknown-linux-musl.tar.gz \
  --repo PeterxVarga/tredven-upstream \
  --signer-workflow PeterxVarga/tredven-upstream/.github/workflows/r20-manual-alpha-provenance.yml \
  --source-ref refs/heads/main \
  --source-digest REAL_APPROVED_MAIN_COMMIT_SHA \
  --deny-self-hosted-runners

# Or run both checks with the source-controlled fail-closed wrapper:
python3 -I -B scripts/verify_signed_alpha.py \
  --dir ./candidate --gh /absolute/path/to/trusted/gh
```

The Python wrapper first runs the existing candidate byte/verifier, verifies original expected manifest `target`, 40-byte source commit, SHA256 of the archive, and calls only the official `gh attestation verify` for cryptography with: repository, signer workflow, default-branch ref, **exact source digest**, and deny-self-hosted-runner policy. Only a nonempty successful verified GH result yields `signature_verified=true`; it **never** sets `release_authorized` or `production_ready` true. Optional `--bundle ./signature/r20-alpha.attestation.bundle.jsonl` is supported for environments without GitHub attestation API access, but offline name-to-current-repository identity is weaker. Do not substitute `SHA256SUMS` alone for signed trust.

## Evidence levels / negative verification

- R20 GitHub workflow syntax checked using existing `actionlint`, but no hosted run can occur before main merge and separately owner-approved manual dispatch.
- R20 verifier has **10/10 isolated unit tests**, some deliberately using *synthetic* `gh` responses solely to exercise policy flags and fail-closed behavior. These are not actual signature verifications.
- Actual unsigned R19 local archive with a non-signature bundle passed candidate-byte checks but was **BLOCKED** by the real pinned GitHub CLI: `GITHUB_ATTESTATION_OR_CANDIDATE_VERIFICATION_FAILED`. The online attempt against GitHub also **BLOCKED** because no matching attestation exists.
- Parent R19 build and benchmark were genuine public-data local E2E, not hosted Sigstore.
- No automatic test or signed public artifact published by R20 until owner-approved deployment of workflow and dispatch.

## Owner-only release gates

**Gate 1:** Examine PR #1, then PR #2, and then the stacked R20 Draft PR with a targeted code + license + security review. All remain Draft. Do not merge automatically.

**Gate 2:** Configure `main` branch protection or a ruleset for a public repository. Protect against direct pushes, force-push and deletion. Consider required PR review/checks appropriate to the actually available reviewers; do **not** require a nonexisting status check, or the branch will be locked. GitHub settings mutation is owner-only.

**Gate 3:** If reviews pass and the owner explicitly approves, merge in dependency order and only then separately manually dispatch the R20 workflow on `main`. The first hosted run needs to be inspected for source SHA, uploaded artifact contents and attestation validity.

**Gate 4:** After an independent verification PASSES, a public GitHub Release may be approved separately. A `workflow_dispatch` invocation is **not** release authorization; a successful signature is also not proof that the OSV child scanner ran or that every dependency is safe.

**Gate 5:** With specific owner approval to contact/announce, invite one independent OSS developer to run cold-start from public release and compare against plain OSV using objective steps, elapsed time, errors and a go/no-go explanation.

## Full project status

PARTIAL. Functional readiness **UNKNOWN (Δ UNKNOWN)**, integrated E2E readiness **UNKNOWN (Δ UNKNOWN)**, public/production readiness **UNKNOWN (Δ UNKNOWN)**: no reproducible whole-product denominator. Locally verified release paths are complete as a narrow slice, hosted signer and external independent install/use remain **NOT RUN**. No production release or revenue claimed.
