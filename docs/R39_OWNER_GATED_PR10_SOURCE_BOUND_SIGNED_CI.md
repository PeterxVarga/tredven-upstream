# R39 — main-isolated, owner-gated exact PR10 signed-CI source qualification

**Date:** 2026-11-23. **Scope:** unblock *one* accurate PR-HEAD → hosted CI → signed build and receipt chain, without merging the unrelated R28–R30–R38 draft development stack and without any deployment, customer-data use or automatic CI trigger.

**Canonical base:** `PeterxVarga/tredven-upstream` protected/default `main` commit `61d1a12d88e822fdfa6ba652115cbf06132614df`; new isolated review branch `feat/r39-main-only-pr10-signed-ci-20261123`. The R39 branch contains only new manual workflow, pure-Python original source/receipt contract, read-only dual-Sigstore consumer, tests and documentation. It **does not include or modify** the R28/R29/R30/R38 Rust draft source changes. The proposed workflow *may inspect/compile the source at one exact, existing draft PR commit* without merging that code.

## ROI challenger and why this slice

1. **Dispatch existing R20 workflow on R30 feature branch:** **reject**. R20 deliberately permits `refs/heads/main` only. Dispatching another ref would be an owner-gate violation/guaranteed skipped job, not a signed PR-head proof.
2. **Dispatch the branch-only R29 workflow or loosen R20 main guard:** **reject**. GitHub `workflow_dispatch` requires the workflow file on default branch, and bypassing current branch restrictions would be unsafe. Main contains only R11 and R20 workflows. The R29 workflow is unmerged, explicitly main/owner-only and attests a *different* PostgreSQL real-app subject and rollback **BLOCKED** status; it cannot honestly be reused as a PR10 release signature.
3. **Merge every preceding draft PR to enable signing:** **reject**. R28–R30–R38 are separate unmerged scopes and have not been owner-approved for integration. No business value justifies that dependency chain merely to qualify one GitHub Actions proof.
4. **Choose an independently reviewable, pin-only manual workflow from main, reuse official GitHub/Sigstore signing and the existing Rust verifier:** **chosen**. The workflow itself remains separate from every draft chain; once owner-reviewed on main, it will fetch PR10 exact HEAD, compile it in a low-privilege build job and let a separate protected-main job attest the archive **and** its exact source/builder receipt.

## Actual current original-source eligibility proof

- [Draft PR #10](https://github.com/PeterxVarga/tredven-upstream/pull/10) remains `open`, `draft`, from same public repo, head `1c8a15ad84858bead99b88e655915975ceefb2e9`, base `44d6eef16de40e33474e578c0ffcd7a2e1b4c698`, with exact branch names. The new `scripts/r39_pr_head_ci_contract.py preflight` passed on a real original GitHub API response. Any PR source-head, base-head, repo/actor or state change must **fail closed** and require renewed owner review. The read-only owner preflight and official-workflow registry are captured as a [sanitized R39 default-branch eligibility receipt](evidence/R39_OWNER_CI_READONLY_ELIGIBILITY_2026-11-23.json) (snapshot, not a signed CI result).
- `main` currently has exactly two GitHub Actions workflow registrations, R11 and R20. Owner-read branch protection was confirmed enabled (`enforce_admins=true`; current approval-count policy is separate). The new R39 workflow **does not exist on main yet**. Therefore no R39 `workflow_dispatch` was attempted; **actual signed PR10 CI evidence is still NOT OBSERVED**.
- The existing signed R20 archive at SHA-256 `ce0524378e0aad328e04813a9003b2211b7c6d24ee7c3fcc87e7ac0e28264a66` remains verified as a **different, main-only source**. The new R39 independent verifier correctly rejects the real R20 run 45059405597 as `HOLD_R39_RUN_NOT_OWNER_MAIN_SUCCESSFUL_WORKFLOW`. It never rebrands the R20 main archive as a PR10 artifact.
- The earlier qualified Tredven Rust/Sigstore verifier SHA-256 `82a235129d523a9da8f36f9e9aedf4427b5cfe36d0c14b23f98242d4b5460809` and already-installed GitHub CLI 2.105.0 SHA-256 `fa7cff06d4db9eee98e00b10ac93beebfe1822109ac04a6cbbf9d806c21d0073` were independently re-hashed successfully in R39. The unsafe default Fedora `gh 2.97.0` is not silently substituted.

## How the main-only, owner-reviewed workflow works *after* explicit owner merge

Workflow path: `.github/workflows/r39-manual-pr-head-ci.yml`.

**Only `workflow_dispatch`; no `push`/PR triggers**. The owner guard checks exact repository, GitHub repository ID, `refs/heads/main`, event, actor and triggering actor, in both jobs. A successful check on a *different* repository, ref or actor is not enough.

1. **Build job — no OIDC/Sigstore permissions:** checkout only reviewed `main` to preserve the trusted Python contract; make a bounded read-only GitHub REST GET for PR #10. Require open draft, own repo ID, exact base/head commits and branch refs. Checkout **exact PR10 SHA** without persisted GitHub credentials. Run the pinned Rust 1.100.0 toolchain, locked Cargo tests, locked release build, package the exact resulting binary into one deterministic `tar.gz`. Produce an **unsigned** receipt from the original protected-main contract, containing PR/base/HEAD, workflow signer commit/run/attempt, archive and inner binary hashes, and explicit `release_authorized=false`, `production_ready=false`. Upload temporary public bytes only; no release or deployment.
2. **Signer job — no checkout or execution of PR code:** with `id-token: write` and `attestations: write` **only in this job**, check out protected `main` and only its reviewed receipt parser. Download the exact prior successful build job's archive and receipt, *re-fetch PR #10* and reject changed heads. Recompute archive and inner binary digests, check workflow identity/run ID and all false authorization fields. Apply the already-pinned official `actions/attest-build-provenance` **twice**, to the actual archive and the exact source-bound receipt separately. Save both official bundles; upload only bounded, seven-day CI artifacts. No code from the PR is executed by the signer.
3. **Independent read-only verifier — already existing Rust crypto:** after a real authorized run, `scripts/r39_verify_signed_pr_head.py` fetches original PR10 and run metadata through the existing qualified `gh api -X GET`, validates the exact source/receipt with `r39_pr_head_ci_contract.py`, then invokes the exact SHA-pinned existing Rust `verify-attestation` **twice**, for the signed archive and for the signed receipt. Both cryptographic records must match the **same** official workflow run, signer, protected-main source/ref, filenames and artifact hashes. **The workflow signing commit on `main` is intentionally distinct from the PR10 HEAD**; the separately signed receipt supplies the trustworthy source link. This fixes the unsafe idea that signing a *different* main-only artifact would prove PR10, without inventing new cryptography.

All three stages remain distinct: a signed workflow artifact is not a scanned vulnerability result, a passed integration/rollback test, a deployed artifact digest, an owner-approved rollout, or a paying business customer.

## Deterministic test and limited real E2E proof levels

- **Real GitHub original-source preflight:** PASS. Actual PR10 metadata read from GitHub and checked against exact pinned branch/base/head. No GH mutation.
- **Offline/synthetic pipeline:** PASS for constructing a tarball and unsigned receipt with mock data, independent recheck of bytes, dates/source/policy and fail-closed tampering/identity tests. The fixture binary is explicitly **not** a compiled PR10 Rust binary and **not signed**; synthetic passing tests are *not a GitHub Actions PASS*.
- **Existing production-quality verifier reused:** local original R20 artifact and pinned Rust/GitHub executable SHA matching verified; previous R20 signature proof remains valid for R20 only. R39 wrong-workflow live replay refused with exit code 2 and no promoted output.
- **Actual GitHub R39 run / signed R39 subjects:** **NOT RUN**, no registered R39 workflow on protected main. The workflow is therefore not production-proven and no assertion of successful cargo build on PR10 is made.
- **Deployment evidence/authorized acceptance:** **NOT VERIFIED**. The current PR's signed build chain cannot yet be made complete. No production mutations or owner approval grants occurred in R39.

## Verification measurements (distinct proof levels)

- **Offline and synthetically instrumented contract/security regression:** 23 R39 tests passed (`OK`); including the original PR SHA/base/branch/repo, owner/main-only event, cargo-stage receipt flags, archive bytes, dual Rust verification report identity, tampered blob/signature/owner/ref rejection, false deployment authorization and output overwrite. A broader compatibility subset of 43 tests on the unchanged R20 verifier and CI helpers reported `OK (skipped=10)`; those skips are **not** counted as independent CI evidence.
- **Actual public-source checks:** original GitHub PR #10 metadata preflight PASS, canonical main SHA and exact two registered workflow paths checked read-only, and the real signed R20 run was **correctly rejected** as an R39 candidate. The existing qualified Rust binary and Github CLI executable digests matched their pinned originals.
- **Static workflow qualification:** official upstream `actionlint v1.7.12` found **0 errors** in the R39 workflow; all **9 inline Bash snippets** also passed `bash -n`. `actionlint`'s optional shellcheck and pyflakes rules were unavailable locally, so static lint is not equivalent to a hosted runner PASS.
- **Not executed:** no R39 GitHub Actions build, PR10 Rust Cargo test, R39 receipt signing or independent dual-attestation verification on actual R39 bytes. The Fedora host has no installed Rust toolchain. These remain **UNKNOWN / NOT RUN** until a separately authorized owner run exists.

## Reproduction and owner gates

Current, always-safe read-only check:

```bash
# Review original GitHub PR HEAD without running CI
GH_REPO='PeterxVarga/tredven-upstream'
gh api -X GET "repos/$GH_REPO/pulls/10" > /tmp/r39-original-pr10.json
python3 -I -B scripts/r39_pr_head_ci_contract.py preflight --pr-json /tmp/r39-original-pr10.json
```

**Owner operation still required:** independently review and merge *only the isolated R39 main-based branch* into the protected `main`, in the usual authorized protected-branch workflow. Merging is **not** approved by this prepared research result; none was attempted. This single scoped operation would register the manual workflow, **not** dispatch it. Any future dispatch requires owner authorization for that exact run after the source pin and workflow are rechecked.

Once correctly registered and separately authorized, the exact, optional manual dispatch is:

```bash
# OWNER ONLY, future after reviewed main merge: NOT RUN in R39
# gh workflow run r39-manual-pr-head-ci.yml -R PeterxVarga/tredven-upstream --ref main
```

After a successful authorized run, download the **two** official generated artifacts to a private local directory before their seven-day expiry and verify the archive and receipt with the exact pinned existing Rust verifier and `scripts/r39_verify_signed_pr_head.py --run-id ... --archive ... --receipt ... --rust-verifier ... --qualified-gh ... --output-dir NEW_DIR`. The CLI itself uses only the exact PR/run public GETs and does not require stored customer tokens or a new signer. A `SIGNED_PR_HEAD_BUILD_AND_RECEIPT_VERIFIED_NO_DEPLOYMENT_AUTHORITY` result, if obtained, would establish only the source-bound build claim, **never** deployment/owner acceptance.

## ROI of the remaining chain and status

**Primary blocker:** reviewed R39 workflow missing from protected main, then no separately authorized actual manual run. Once it is registered and signed build provenance exists, the next useful technical proof is the exact artifact digest in a **disposable/staging** deployment plus role-accepted change/rollback; that requires a separate explicit owner/runner approval and must reuse the existing GitHub native attestations/verifier. Do not build another scanner or cryptographic framework, nor treat GitHub native capabilities as a gap without a buyer loss case.

**Whole-project functional %, integrated business E2E %, production readiness % (and Δ): UNKNOWN.** No reproducible product-level denominator, authenticated paid buyer, signed R39 CI run, deployed artifact or accepted rollout is present. A reviewable workflow is not production capability.

**Safety:** NO_SEND, NO_MERGE, NO_DEPLOY, NO_WORKFLOW_DISPATCH, NO_NEW_TOKEN, NO_PRIVATE_CUSTOMER_DATA, NO_PAID_API. No workflow modifications to current protected main or previous PR branches. No GitHub Actions were launched.
