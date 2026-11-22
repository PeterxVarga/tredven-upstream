# R21 — Main protection and stacked Draft PR targeted review

Date: **2026-11-22**. Repository: `PeterxVarga/tredven-upstream` (public/personal). This is a bounded owner-scope review, **not** a merge or release authorization, exhaustive audit, legal opinion, or hosted CI run.

## Objective, scope and ROI choice

End-user capability sought: a protected default branch with transparent, reviewable commits and a credible first official Sigstore-signed Linux alpha; eventually a genuine independent developer cold-start user test. Bounded review covers the existing PR #1 (foundation), PR #2 (first use, actual advisories, license archive, portable Linux) and PR #3 (manual owner-gated alpha provenance), in dependency order, without merge, workflow dispatch or release.

ROI challenger: immediate merge/hosted workflow is unsafe and still owner-gated; building more scanner/billing functionality does not resolve signed release trust; an overstrict requirement for a nonexistent CI job or unavailable second reviewer could deadlock a solo open-source repository. Therefore: add **minimum effective GitHub main protection**, reuse past credible R15–R20 local evidence, inspect the dangerous trust edges, run one native real public dependency scan, and fix the one actual first-user security-disclosure inconsistency found.

## Canonical checked state and actual protection mutation

- Remote `main` before and after: `42a749d9845dcfb4eb553760021e42c035b981c4`; no merge occurred.
- PR #1: https://github.com/PeterxVarga/tredven-upstream/pull/1; base `main`, head `5ad21855d9bbbfcb33625ca6d5af37017c22a26d`, **11 commits / 55 files / Draft**, no reviews or inline review comments.
- PR #2: https://github.com/PeterxVarga/tredven-upstream/pull/2; base PR #1 branch, head `876df9375d61cf3d94e8597439f9ec0d2cea396c`, **6 commits / 15 files / Draft**, no reviews or inline review comments.
- PR #3: https://github.com/PeterxVarga/tredven-upstream/pull/3; base PR #2 branch, initial head `d29de6ae659bf0219cd268a99aedd5908bb9e5c9`, **1 commit / 5 files / Draft** at review start, no reviews or inline review comments. R21 adds this bounded disclosure/review document to its review branch; re-check the final SHA after that commit.
- Before owner-scope protection: `GET /repos/PeterxVarga/tredven-upstream/branches/main/protection` returned 404 and the repository rulesets list was empty.
- **Actual owner-authorized GitHub mutation performed:** `PUT /repos/PeterxVarga/tredven-upstream/branches/main/protection`; then an independent `GET` confirmed: `enforce_admins=true`, PR requirement enabled, `required_approving_review_count=0`, `required_status_checks=null`, `allow_force_pushes=false`, `allow_deletions=false`, `required_conversation_resolution=true`, `lock_branch=false`.
- No imaginary required CI status; 0 GitHub Actions runs when checked. This is **PR-gated admin-enforced protection**, not externally approved or CI-attested code quality. Repository owner with administrative settings rights can change the policy later. An unauthenticated or simulated direct-push denial was not counted as extra proof.

## #1 Foundation: targeted review verdict

**LOCAL_TARGETED_REVIEW_PASS / HOSTED_SIGNED_CI_NOT_RUN / NO_MERGE_APPROVAL.** Reused already preserved R15 security review (`docs/R15_PR1_SECURITY_REVIEW.md`) and R20 aggregate native regressions instead of rerunning unchanged components. Key trust boundaries checked: manual-only `r11-manual-public-osv-attest.yml`, exact GitHub action SHAs and repository/ref guards, source/tag and signed-CI receipt binding, no automatic deploy/merge authorization. R15 had already reproduced and fixed a cross-record verified workflow URI mismatch and recorded focused regression tests. R21 did **not** independently audit every line in the 55-file PR. Missing: first hosted signed public OSV scanner-reference run, independent signature and actual actor proof.

## #2 First-use/portable alpha: targeted review verdict

**LOCAL_PUBLIC_DATA_E2E_PASS / RELEASE_NOT_PUBLISHED / NO_MERGE_APPROVAL.** Checked the source-scope fix, bounded advisory identities, original R12 third-party Cargo.lock attribution, explicitly opted-in SHA-pinned OSV binary acquisition, `review-local` human-visible output, portable musl static link and Rust/musl runtime notices. The existing R19 extracted real public `sharkdp/fd` v10.4.2 -> v10.5.2 scanner test produced three resolved advisories and conservative REVIEW. Cache origin/digest pin is not independent upstream publisher Sigstore and a local same-user path-race remains a boundary. This is not a complete security certification or legal approval.

### Fresh native dependency inventory corroboration (public repo only)

- Real official upstream OSV-Scanner **v2.7.1** pinned SHA256 `fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8`, direct scan command: `scan source --lockfile /absolute/path/Cargo.lock --all-packages --no-resolve --format json`.
- Actual current `Cargo.lock` SHA256: `997f8aae07956cee112a05d0ad65a2b5d899771aa0b3b7eb0f0673ac527301ad`.
- Scanner reported **22 package entries** in **one** results section, **0 reported vulnerability occurrences**, exit **0**. The release legal annex separately counts **21 registry packages**; the total 22 includes the project's own package. These figures are from different intentional scopes, not a discrepancy.
- Result JSON was parsed and its source path was confirmed to be the actual repository `Cargo.lock`. Original scan evidence is stored only in the ignored owner-local `output/r21-public-dependencies-20261122/` with private directory/file permissions. Scan queries public OSV; all package inputs were from the already-public repository.
- Scope limitation: this is a point-in-time advisory check of the lockfile, **not** a dependency license sufficiency determination, GitHub-hosted signed scan, malicious-package detection, or proof of zero vulnerabilities outside OSV's reported dataset.

### Concrete root-cause fix made during R21

`SECURITY.md` still opened with the obsolete **source-only** assertion and claimed globally that the CLI *never runs a scanner*, even though R17/R18's explicitly permitted executable OSV path already exists. This could mislead OSS users about downloads and dependency metadata leaving their machine. The minimum correction scopes the no-scanner claim to `inspect-scan`, updates the pre-alpha description, and documents the exact R18 download, explicit public-network consent, cache/verification limits and R20 signing trust boundary. No Rust runtime, CLI safety guard or PR1 source behavior changed.

## #3 Signed alpha: targeted review verdict

**STATIC_POLICY_PASS / REAL_SIGNED_ALPHA_UNKNOWN / NO_MERGE_APPROVAL.** Existing R20 owner-only workflow is `workflow_dispatch` on exact `main`, repo ID and actor; hosted runner, read-only contents, pinned GitHub actions, exact signed `.tar.gz` subject, independently verifiable bundle and 7-day Actions artifact retention. No `push`/`pull_request` trigger, automatic release, deployment or data export. Official `gh attestation verify` is used, with exact repository, signer workflow, `source-ref` and `source-digest`. The real **unsigned** R20 archive was correctly rejected. Prior tests: **171 Rust**, **24 release/license**, **10 CI receipt**, **10 synthetic policy** PASS, and `actionlint` PASS. Test mocks were not counted as actual signatures. No hosted GitHub Actions run exists.

## Accepted gates / remaining blockers

- Branch protection is **ACTIVE**. Draft PR #1, #2 and #3 are still **UNMERGED**. A reviewer still needs to assess the complete large PR #1, the privacy/runtime details in #2, and the hosted workflow in #3 before owner-approved merge.
- There is **no required hosted CI status** configured because no such verified job is available yet. A successful local regression is not the same as a hosted PASS.
- The first real signer run requires the code present on approved protected `main` after separate merge permission; manual `workflow_dispatch` and any publication remain separate approvals. Hosted signature and independent outsider adoption are **NOT RUN**.
- No public GitHub Release, production deployment, secret access or external developer outreach was requested or performed.

## Project status

Overall **PARTIAL**. Functional readiness **UNKNOWN (Δ UNKNOWN)**; integrated E2E readiness **UNKNOWN (Δ UNKNOWN)**; production-use readiness **UNKNOWN (Δ UNKNOWN)**. Whole-project reproducible percentage denominator still does not exist; narrow local public-data E2E and the exact branch-protection API result are measured outcomes, not full project readiness.

Next highest-ROI real-world slice after owner sign-off: merge reviewed stacked PRs in order #1 -> #2 -> #3, manually run the on-main provenance workflow, independently verify the resulting signed archive and source identity, then perform one approved genuine independent developer cold-install/use study versus upstream OSV. Avoid more framework development until those downstream gates are measured.
