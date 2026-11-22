# R23 — protected-main merge rehearsal and owner-ready signed-alpha gate

**Date:** 2026-11-22. **Owner-scoped status:** local integration exercise and review-only Draft PR; **NO MERGE, NO DISPATCH, NO PUBLIC RELEASE, NO EXTERNAL OUTREACH**.

## Actual user capability sought

Reach a dependable GitHub-provenance-verified Linux alpha from the four review branches, then enable an external developer to cold-install it and judge upgrade decisions versus OSV-Scanner. A successful local test is not the whole E2E; the remaining hosted and human stages are explicitly separate.

## ROI Challenger (before writing code)

- **Immediate merge and public release:** highest distribution speed but skips outstanding owner-gated review, hosted first-run provenance and real-user evidence. Not authorized in this round.
- **Add features / Teams backend / proprietary scanners:** duplicates OSV/Renovate or creates billing without demand. Not on the current user critical path.
- **Copy an OSS release framework / additional custom signing system:** GitHub's official provenance action and the existing verified local release-candidate builder already cover this. Redundant and higher security surface.
- **Selected:** isolate and exercise the actual four staged PR merges on the precise published parent branch, prove the full code tree matches the reviewed head, discover/remove the first integration blocker and perform an exact-source offline release build plus real public-data cleanroom. Preserve distinct owner approval of merge/dispatch/release.

## Canonical read-only GitHub state at start

- Remote `main`: `42a749d9845dcfb4eb553760021e42c035b981c4`, protected (PR-only, admin-enforced, force push/deletion disallowed).
- Draft PR #1 `main` → `5ad21855d9bbbfcb33625ca6d5af37017c22a26d`.
- Draft PR #2 stacked on #1 → `876df9375d61cf3d94e8597439f9ec0d2cea396c`.
- Draft PR #3 stacked on #2 → `3688387da68debcbe0358b08a63fea7ff19c9d5d`.
- Draft PR #4 stacked on #3 → `08740f83f411606a45720217ef5d356ca7fbe045`.
- GitHub Actions runs = 0; GitHub Releases = 0. No hosted signature/verifier claim is possible.

## Reproduced four-stage merge tree — isolated, NOT a GitHub merge

The separate ignored detached worktree `output/r23-stacked-integration-dryrun-20261122/checkout` began from the exact `origin/main` SHA. Four actual `git merge --no-ff --no-edit` operations of the four branch heads in dependency order completed without conflicts. The resulting combined Git tree SHA was **`e9409e6a0ae36e5995955468d0c4178731a480d3`**, exactly the source tree of the reviewed PR #4 head. No remote ref, protected branch, open PR metadata or release was mutated by this test.

## Reproduced integration failure & minimal root fix

On the first combined-source regression with the same Cargo target directory previously shared between worktrees, `reusable_json_policy_verifies_real_public_release_offline` returned exit 2 instead of 0. Comparing genuine verified-public-release fixture commands established:

- From the original repository's example policy location with pinned `gh 2.105.0`: **VERIFIED**, exact public upstream workflow and signed artifact.
- From the merged detached worktree's otherwise identical example policy location: **BLOCKED / ATTESTATION_FILE_UNAVAILABLE**.
- Root mechanism: a checked-in example policy contains relative paths to ignored `../output/r9-public-signed-fixture`, but the optionally supplied fixture exists only in the original repository's ignored output; Git worktrees do **not** copy untracked fixtures. The test assumed a repository-local fixture even though `TREDVEN_R9_PUBLIC_FIXTURE_DIR` explicitly points elsewhere. The shared Cargo target could also reuse a compiled test binary with the wrong compile-time `CARGO_MANIFEST_DIR` between worktrees.
- Fix confined to `tests/attestation_cli.rs`: read the same source-controlled example JSON; override **only** the bundle and trusted-root file paths in a temporary copy with the two paths supplied by the explicit external fixture directory. All existing repository ID, signing workflow, ref, commit, predicate, signature and authorization gates remain unchanged.
- Verified the previously failing real-public-Sigstore fixture on the corrected source with a **separate Cargo target directory**: PASS. Followed with the full Rust test suite on that isolated target: PASS. This was a test environment coupling, **not** a weakened signature check or proven runtime scanner failure.

## Exact release qualification acceptance

With a clean, committed R23 review branch, replay the final corrected R23 commit into a fresh detached merge rehearsal against the protected main root, compare final Git trees, run fmt, offline Clippy, full Rust tests, Python release/licensing and CI/signing policy tests, and two workflow `actionlint` checks. Use a **worktree-isolated Cargo target**, pinned Rust 1.100.0, and existing read-only public fixture env.

Then run `scripts/release_candidate.py build --portable-musl` and `verify` on that exact locally merged clean commit; reject missing Rust runtime and crate notices, non-static ELF or any incorrectly granted publication rights. Run the **extracted** candidate with existing R22 cleanroom harness (Debian 12, unprivileged user, public `sharkdp/fd` 2-tag source, native OSV parity). This yields an **unsigned isolated merge-rehearsal candidate**, not a GitHub-attested release.

Store concrete actual receipts and local tarball SHA only under the ignored `output/r23-stacked-integration-dryrun-20261122/` directory. Do not commit scanner report bytes or misleading 'signed' test artifacts.

## Conditional owner sequence after all local gates

1. Owner examines PR #1 → #2 → #3 → #4 and this R23 fix PR; review critical trust / license points and decide on merge separately. No merging as part of this review.
2. Keep each stacked base branch available while retargeting the next PR to protected `main` after its parent is integrated. Avoid auto-deleting a branch still used as another PR base. Perform merges in exact dependency order and verify final `main` Git tree equals the reviewed tree; Git commit hashes may legitimately differ by merge strategy.
3. Only after approved merges and owner consent, manually dispatch the R20 signer workflow on the **actual** protected `main`. Inspect hosted Rust build, exact source SHA, signed tarball subject, attestation `bundle-path` and GitHub-hosted signer identity. Any failure is a release **HOLD**, not permission to bypass the attestor.
4. Separately approve public GitHub alpha Release from that verified archive and label source/compatibility limitations. The local unsigned candidate must **not** be published as the signed release.
5. Only after outbound contact approval, enroll 2–3 independent Rust developers on public data; assess unaided install, correct upgrade decision, errors/time and incremental value over the official OSV PR Action. No claims of product-market fit from synthetic tests.

## Whole-project status

**PARTIAL**. Functional readiness **UNKNOWN (Δ UNKNOWN)**; integrated E2E **UNKNOWN (Δ UNKNOWN)**; production-ready **UNKNOWN (Δ UNKNOWN)** without a reproducible whole-project denominator. Local public-data and synthetic-merge evidence are valid only for their named test environment; actual GitHub-hosted signer, public Release and independent human value remain **NOT RUN**.
