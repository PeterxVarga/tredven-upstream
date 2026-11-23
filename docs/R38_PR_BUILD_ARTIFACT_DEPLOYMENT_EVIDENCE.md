# R38 — one real PR → signed build → deployment and owner-acceptance evidence chain

**2026-11-23.** Public, source-specific **Tredven Upstream** verification on branch `feat/r38-pr-artifact-deployment-evidence-20261123`, based on the **unmerged R30** feature branch `feat/r30-github-zero-to-value-20261122` at commit `1c8a15ad84858bead99b88e655915975ceefb2e9`. This is **not** the unrelated SEOS project. The R29/R30 draft PRs are not merged or released.

## ROI challenger / accepted scope

1. Build a new GitHub Actions/CD orchestrator or deploy an upgrade to obtain a full green chain — **rejected**: changes owner/production boundaries and creates operational risk before proving a missing buyer job.
2. Add generic support for ten CI vendors and signers — **rejected**: would duplicate existing `attestation.rs`, GitHub CLI and R30 workspace for an unproven wedge.
3. Reuse a **real existing GitHub Actions release artifact, existing signed Rust verifier, actual R30 PR, original API checks and deployment records** in one narrow fail-closed source correlation — **chosen**. The tool records the first genuine evidence discontinuity, not an invented successful deployment.
4. Defer entire chain and validate Recycling buyers first — credible larger cross-lane monetization alternative, but this user-approved work was only the Tredven Upgrade Tool lane.

## Actual externally verified source chain (read-only)

| Stage | Original source | Exact outcome |
| --- | --- | --- |
| **PR** | [R30 draft PR #10](https://github.com/PeterxVarga/tredven-upstream/pull/10) | **HEAD `1c8a15ad84858bead99b88e655915975ceefb2e9`**, draft `open`, base R29 at `44d6eef16de40e33474e578c0ffcd7a2e1b4c698` |
| **Build workflow** | [R20 GitHub Actions run 45059405597](https://github.com/PeterxVarga/tredven-upstream/actions/runs/45059405597) | Successful **manual `workflow_dispatch` on `main`**, **HEAD `61d1a12d88e822fdfa6ba652115cbf06132614df`**, GitHub-hosted signer workflow `r20-manual-alpha-provenance.yml` |
| **Signed archive** | R20 `r20-alpha-candidate-bytes` Action artifact with separate `r20-alpha-attestation-bundle` | Original `SHA256SUMS` rechecked 3/3; exact archive SHA-256 `ce0524378e0aad328e04813a9003b2211b7c6d24ee7c3fcc87e7ac0e28264a66`; the **official GitHub/Sigstore verifier** verified the SLSA provenance and exact run |
| **Existing Rust verifier** | `tredven-upstream verify-attestation`, from the originally signed R20 archive | `VERIFIED`, `SIGNED_ARTIFACT_PROVENANCE_AND_EXACT_IDENTITY_VERIFIED`, verified GitHub Actions run `45059405597/attempts/1`, no deployment/release permission |
| **PR checks** | GitHub original commit check-runs API for R30 `1c8a15...` | **0 reported check-runs**, so no successful exact PR-bound check can be attached to the signed R20 run |
| **Deployment** | GitHub original deployments API queried for R30 PR HEAD and R20 signer HEAD | **0 GitHub deployment records for either inspected commit**. This is not evidence that no deployment exists outside GitHub. No cryptographically verified deployed artifact digest |
| **Owner approval** | No signed, role-accepted deployment approval receipt in the scoped evidence | **UNKNOWN / NOT VERIFIED**, not owner-approved by a CI success result |

The **GitHub Actions artifact ZIP** digest is the digest of GitHub's storage ZIP, **not** the inner signed `.tar.gz` archive. R38 checks official workflow-run provenance for both stored artifact entries and independently matches the inner tarball hash to the original release manifest **and** the cryptographically verified attestation subject. The pre-signing manifest explicitly says `signature_verified: false` and `production_ready: false`; it is never treated as a post-signing authorization claim. The signature verification is performed by the **existing Rust CLI using the official GitHub CLI**, not reimplemented in Python.

### Qualified toolchain and an actual failure resolved without weakening policy

The Fedora default `gh 2.97.0` was **correctly blocked** by the existing Rust verifier with `GH_ATTESTATION_VERIFIER_VERSION_NOT_QUALIFIED` (GHSA policy fix requires `gh >=2.102.0`). Reused the earlier **already-installed `gh 2.105.0`** at the owner's separate toolchain, with original SHA-256 `fa7cff06d4db9eee98e00b10ac93beebfe1822109ac04a6cbbf9d806c21d0073`. The signed R20 Rust binary's own SHA-256 was `82a235129d523a9da8f36f9e9aedf4427b5cfe36d0c14b23f98242d4b5460809`. R38 *pins both executables' SHA-256* before invoking them. No policy bypass and no new binary download was needed.

The existing GitHub-hosted Action artifact metadata showed **two unexpired stored ZIP artifacts on 2026-11-23**. Their announced expiry was **2026-11-29**. Reproduce the download while it is available; original signature provenance or another copy of the bytes must be independently obtained if the downloadable Action artifact expires.

## New narrow reusable verification capability

`python3 -B scripts/r38_pr_build_deployment_probe.py` performs only these bounded operations:

- Verify the exact pinned local Rust verifier and qualified GitHub CLI executable SHA-256; no user-supplied binary can manufacture `VERIFIED`.
- Read **only** `GET` GitHub public `pulls/{id}`, `actions/runs/{id}`, that run's artifact metadata, the PR-head commit's check-runs and deployments. The repository is hardcoded to `PeterxVarga/tredven-upstream`. No arbitrary API endpoint, deployment command, workflow dispatch or private connector request.
- Hash the original bounded local release archive and manifest; call the **existing Rust verifier** with pinned source-run/signer policy and GitHub's actual SLSA evidence.
- Compare PR head ↔ workflow run head ↔ signed archive subject/run identity, and refuse to count a signed build for an **unrelated** PR commit.
- Keep deployment and explicit authorized owner acceptance as **NOT VERIFIED**, even if a GitHub deployment record exists, because a status alone does not prove the **same signed artifact digest** was installed and accepted.
- Write only a **new** local `r38_evidence_chain.json` and `r38_evidence_chain.md`, with no raw credentials, addresses or source bodies.

Example for this fixed, already-existing real run after downloading both R20 Actions artifact ZIPs through the standard GitHub CLI and extracting the signed R20 binary into an isolated local folder:

```bash
python3 -B scripts/r38_pr_build_deployment_probe.py \
  --pr 10 --run-id 45059405597 \
  --artifact /isolated/r20-alpha-candidate-bytes/tredven-upstream-v0.1.0-x86_64-unknown-linux-musl.tar.gz \
  --manifest /isolated/r20-alpha-candidate-bytes/manifest.json \
  --rust-verifier /isolated/r20-verified-binary/bin/tredven-upstream \
  --qualified-gh /path/to/previously-qualified/gh-2.105.0 \
  --output-dir /tmp/new-r38-evidence-only
```

The actual 2026-11-23 owner Fedora read-only run produced:

The **machine-readable sanitized original-source receipt** is committed at [R38 original GitHub signed-chain JSON](evidence/R38_ORIGINAL_GITHUB_SIGNED_CHAIN_2026-11-23.json), SHA-256 `6f0032a4e8cd282964d366a59a746315ac5b1d760bd6612e28346319d8516aec`. It contains only public GitHub source identifiers, digests, verified stage classifications and safety decisions; not the downloaded archive, source comments, GitHub credentials or any customer data.

```text
signed R20 artifact: VERIFIED against exact workflow/main source
PR head:          1c8a15ad84858bead99b88e655915975ceefb2e9
signed run head:  61d1a12d88e822fdfa6ba652115cbf06132614df
PR check-runs:    0 for the checked PR HEAD
GitHub deployments: 0 for the checked PR HEAD
owner acceptance: NOT VERIFIED
RESULT: HOLD_PR_TO_SIGNED_BUILD_SOURCE_MISMATCH
production_ready: false
performed_external_mutations: false
```

This is a **genuine public GitHub original-source and cryptographically verified signed artifact** example, **not** a PR-triggered release, not an R29 signed upgrade test, not a real deployed product upgrade, and not commercial buyer proof. R29's manual signed real-app workflow in its draft PR remains unexecuted in the checked evidence. R38 never opens a PR, pushes code, performs paid API queries, sends messages, touches production data or dispatches a new workflow.

## Acceptance, primary blocker and next best ROI

- **Technical accept:** original R20 archive bytes and official SLSA proof verified; source PR and workflow details confirmed via live GitHub GET; exact SHA mismatch blocks; deployment/acceptance remain correctly UNKNOWN; negative tampering tests and no-write test pass. **32 Python integration/security tests passed** across the new R38 chain, existing R20 signed alpha tests, and R29 manifest safety tests. Real signed Rust binary verification also passed using the exact pinned Rust and GitHub CLI hashes. The Fedora environment has no Rust/Cargo compiler; **a fresh Cargo suite for the unchanged Rust sources was not rerun**, and no Rust sources were changed in R38.
- **Primary E2E blocker:** no approved hosted CI and matching artifact **for the actual R29/R30 PR HEAD**, before even starting to argue deployment equivalence. The real R20 `main` archive cannot be repurposed as their successful PR evidence.
- **Next best ROI:** first a separately owner-authorized **PR-head-bound manual CI proof** reusing existing R29 workflow and attestation core, then read-only comparison against exact deployed digest and role-approved acceptance from an appropriately scoped **disposable/staging** environment. A production deployment or private customer artifact is **not** authorized by this review.
- **Commercial gate:** after existing Renovate/Snyk/GitHub controls, a real buyer must still demonstrate recurring residual work and hosted WTP. No additional scanner, native signer, deployment agent or SaaS launch is justified solely by this study.

**Whole-project status:** functional %, integrated business E2E %, production readiness % and all respective deltas remain **UNKNOWN**: no fully enumerated project-level denominator or buyer/production transaction evidence. This bounded read-only proof has no production readiness implication. **NO_SEND / NO_MERGE / NO_DEPLOY / NO_WORKFLOW_DISPATCH / NO_PAID_API / NO_PRIVATE_CUSTOMER_DATA.**
