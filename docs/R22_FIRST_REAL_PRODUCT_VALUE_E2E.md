# R22 — First Real Product Value: full vertical acceptance & falsification

Date: 2026-11-22. Repository: PeterxVarga/tredven-upstream. Branch: feat/r22-first-value-cleanroom-pilot-20261122, based on R21 `3688387da68debcbe0358b08a63fea7ff19c9d5d`. This record distinguishes local/public cleanroom rehearsal from an actual external user study.

## Entire outcome, not another tooling milestone

**Ultimate user capability:** a developer without our prepared Fedora files downloads an **official, owner-approved, independently signed** Tredven Linux x86-64 alpha, verifies its GitHub/Sigstore provenance, runs a review of two legitimate public Rust Git tags without authoring JSON or installing the scanner manually, and arrives at an evidence-backed, correctly limited go/no-go **human review**. They can articulate the extra value versus plain OSV-Scanner and the official OSV GitHub PR Action.

**Acceptance evidence hierarchy:** (1) local static/negative tests, (2) read-only public-data scan on existing workstation, (3) **fresh independent Linux image/container, real public Git clone + cold OSV cache + direct OSV parity** (R22 local acceptance), (4) official GitHub-hosted signed artifact and current-source attestation verified independently, (5) at least one unaided independent developer cold install and user-value measurement, ideally 2–3 testers, (6) separate authorized public release. Never equate a lower level with a higher one.

**Approvals:** owner-controlled merge, workflow_dispatch, public release and external contact remain separate. This round may prepare, validate and create a Draft PR, but cannot assert those actions have been authorized.

## Mandatory ROI challenger

1. Host Teams payments/auth/UI now: no demonstrated multi-repo paid demand; expensive, defer.
2. Duplicate OSV-Scanner/Re­novate's existing PR delta scanners: official OSV Action already flags new PR vulnerabilities and Renovate already creates update PRs; feature parity is not defensible product differentiation. Defer.
3. Only do the next signing workflow or another short regression: necessary but insufficient to establish user value and repeated before; bundle it into a meaningful full E2E.
4. **Selected:** build a self-service cleanroom technical proof and a repeatable competitor comparison on genuine source objects; identify the actual first-user blocker; package a falsifiable external developer study and close every safe local vertical before waiting for owner-authorized external launch.

## Direct comparison and falsification

- Test on an independently public real repository, fixed to two actual release tags, with exactly identical root Cargo.lock bytes and pinned OSV-Scanner v2.7.1 binary.
- Native baseline: run official OSV CLI for *both* source-tag lockfiles with the exact same `--all-packages --no-resolve --format json` flags as Tredven; do not compare a single scan against two Tredven scans or call scanner exit 1 a process failure.
- Tredven: execute extracted static Linux CLI with `review-local --install-pinned-osv --allow-public-osv-network`; verify actual tag commits, original native scanner finding counts and conservative output, then repeat with the verified cache.
- **Observed cleanroom fixture property:** OSV JSON embeds the unique, private temporary Cargo.lock path. Therefore raw scanner report SHA-256 values and the raw delta subject path legitimately change across identical repeated runs. Preserve exact raw report digests for evidence-integrity proofs, but measure semantic consistency using tagged source commits, lockfile hashes, scanner counts/advisory identities, comparable scope and decisions. Do not silently rewrite scanner bytes or claim the raw byte hashes should be stable.
- Compare observables, not a fabricated composite score: clone/first-use wall time, native OSV calls, warm-cache time, number of manual interactions/commands, scan parity, real decision, attribution of which evidence is source-bound, privacy and signature limitations. One execution is not a statistically sound speed claim.
- Explicitly ask independent testers whether a baseline-vs-candidate advisory count plus Git changed paths is useful beyond the **already available OSV GitHub PR Action**. If not, prioritize a narrower evidence/audit problem or stop; do not claim broad uniqueness.

## Real-world human pilot protocol (only after owner-approved signed alpha release)

- Recruit 2–3 independent Rust developers with *no prior onboarding* and a public, permissioned Rust repository with two legitimate tags; do not contact them without an explicit outbound approval. Avoid private source/lockfiles and do not request secrets.
- Give each the approved GitHub Release page, verification instructions and the OSS competitor baseline. Let them obtain the CLI unaided and verify the full signer workflow, source SHA and artifact digest before execution.
- Alternate task order between native OSV and Tredven when possible; capture time to an **accurate explanation** of the new/resolved/persistent advisories, changes and what is *not* deploy-authorized. Count actual interventions, installation errors, misunderstood warnings, and willingness to use it again.
- Do not turn a successful command into 'value delivered' without a human making a correct and useful decision, and do not misattribute the native OSV database's discoveries to Tredven.
- Do not store personally identifying pilot recordings or private project files. If testers volunteer anonymous aggregate feedback, document consent and provenance.
- **Go** if the additional source-bound readable review is consistently useful without heavy onboarding; **pivot** if the biggest unmet need is PR-native/CI integration or auditable history; **stop/defer expansion** if plain OSV/Renovate already solves the task at equal or lower friction. No arbitrary success percentages.

## Current gates / status

- GitHub `main` is PR-protected, admin enforced; Draft PR #1 → #2 → #3 remain unmerged. R20 manual signing workflow exists only on feature branch. Hosted Actions count 0, Release count 0 at R22 start.
- Known unsigned clean-source R20 archive SHA256: `69e6636258920f815b777ae913bbd3c2b01799731c875fd24991973a1e5644de`; it is a *local technical fixture only*, not a public release, signer-verified artifact or endorsement for outsiders to execute.
- R22 cleanroom evidence will be stored only under ignored output/r22-cleanroom-pilot-20261122/evidence, with no secret material. Exact observed timing and parity are reported only after the run.
- Overall project: **PARTIAL**. Functional readiness UNKNOWN (Δ UNKNOWN); integrated E2E readiness UNKNOWN (Δ UNKNOWN); production readiness UNKNOWN (Δ UNKNOWN), since no reproducible whole-product denominator exists. E2E technical rehearsal completion does not make the project production ready.

**Next ROI gate:** separate owner-approved PR integration and hosted signer run, verified GitHub Release, and independent external user trial. Choose next product capability from those actual outcomes, not more pre-emptive frameworks.

## Executed R22 cleanroom technical slice — PASS, not a public/user launch

The following has actually been executed on 2026-11-22, not just planned:

- **Independent operating environment:** newly launched Debian **12.15** rootless Podman test container, Python **3.11.2**, Git **2.39.5**, curl **7.88.1**, system CA certificates. A separate local Debian 12 test image is built from `tests/cleanroom/Containerfile`; this is a local image, not a pushed container or reproducible pinned Debian package snapshot.
- **Security/test boundaries:** the only host mounts are source-controlled cleanroom code (read-only), an owner-local **unsigned** R20 candidate archive (read-only), and a new private ignored evidence folder (write-only for result capture). The actual trial runs as the container's unprivileged `nobody` user with a new empty HOME/OSV cache; no GitHub/Vercel/cloud authentication or secret directory was mounted. Public Debian/Docker Hub/GitHub/OSV traffic is explicit.
- **Archive provenance:** local R20 release candidate only, source commit `d29de6ae659bf0219cd268a99aedd5908bb9e5c9`, exact archive SHA-256 `69e6636258920f815b777ae913bbd3c2b01799731c875fd24991973a1e5644de`, binary SHA-256 `a98cfaa62a160f21742d1c2600de00da2695f97301a082af0d018c4a2cc409e0`. Independent local verifier passes. It has **NO official Sigstore artifact verification or release authorization**.
- **Real public source:** fresh `git clone --no-checkout https://github.com/sharkdp/fd.git` inside the container; baseline `v10.4.2` commit `7027d45303b412be6fa9c09d689cc6276748fb38`, candidate `v10.5.2` commit `b2a287b3993768e0ec52f0852916917f23fb2a38`. Both have real root Cargo.lock objects.
- **Native OSV independent baseline:** official v2.7.1 Linux amd64 asset, exact SHA `fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8`. Direct native CLI scanned both Git-tag snapshots with the same `--all-packages --no-resolve --format json` options. It observed **126 packages/3 advisories** before and **95 packages/0 advisories** after. The three resolved IDs were `RUSTSEC-2026-0190` (anyhow), `RUSTSEC-2026-0204` (crossbeam-epoch) and `RUSTSEC-2026-0486` (rustix).
- **Tredven outcome matched:** on the same Git objects and the same pinned upstream scanner bytes, decision `REVIEW`, 3 resolved, 0 new, source subject matched and no production/release authority. Its report additionally includes tagged Git commits and changed-path summary. This does **not** make Tredven the vulnerability source or establish superiority over OSV's own PR Action.
- **One-command wrapper proved:** `scripts/r22_cleanroom.sh` parsed explicit consents, checked the exact archive SHA, invoked the existing release-candidate verifier, built/reused the Debian image, then ran `tests/cleanroom/first_use.py` and saved bounded reports without overwriting prior output. Final observed wall-time values **within this one run**: Git clone 1.523 s; Tredven **fresh cache 14.832 s**, warm cache 2.046 s; two direct native OSV scans 1.177 s + 0.723 s. Do not treat these as representative performance statistics.
- **Negative cases:** no network consent, wrong expected archive SHA, missing explicit pilot SHA, and missing first-use public-network consent were rejected before network or scanner execution. Real R20 unsigned artifact still fails the separate GitHub Sigstore verifier, as expected.
- **Raw vs semantic invariance:** exact unmodified OSV JSON embeds a randomized, private temporary Cargo.lock path, so raw report digests and the `delta.subject` temporary path differ across repeated runs. That is correct byte-level evidence behavior, not contradictory findings. Separate checks establish stable Git source SHA, input Cargo.lock hash, scanner decisions, advisory counts and delta classification. No scanner bytes were rewritten to manufacture hash equality.
- Initial harness attempts revealed *harness-only* environment gaps: nonprivileged access to the mounted 0700 host script and Python 3.11.2 lack of `TarFile.extractall(filter=...)`. Both were corrected before the final proof. These were not Tredven runtime defects.

### Reproduce with one explicit local command (requires Podman, Linux and public egress)

From a trusted checkout of the R22 code branch, with its R20 unsigned test candidate already present under ignored `output/`:

```bash
bash scripts/r22_cleanroom.sh \
  --candidate-dir "$PWD/output/r20-unsigned-local-candidate-d29de6a" \
  --archive-sha256 69e6636258920f815b777ae913bbd3c2b01799731c875fd24991973a1e5644de \
  --output-name r22-my-unique-cleanroom-run \
  --allow-public-network --allow-unsigned-local-candidate
```

The wrapper deliberately refuses repeated output names, missing consent and hash mismatches. It installs **no** production software on the host, writes no private source data, and performs no provider mutations beyond read-only public queries/downloads. The separate local container image is 211 MB and can be removed by the owner when no longer useful. External users must **not** substitute this unsigned rehearsal for signed-release installation.

### Observed receipt locations

- First independent-environment acceptance: `output/r22-cleanroom-pilot-20261122/evidence/receipt.json` (one sample).
- Reproduction from the tracked Python source: `output/r22-cleanroom-pilot-20261122/tracked-evidence/receipt.json`.
- Final one-command wrapper acceptance: `output/r22-one-command-e2e-20261122/evidence/receipt.json` plus original native OSV JSON and the Tredven cold/warm reports. All kept under locally ignored `output/` — **not committed or publicly uploaded**.

## Acceptance gate outcome at R22

- Cleanroom Linux startup, exact local test bytes and visible safety decisions: **PASS**.
- Real independent public fd Git clone, two-tag OSV consistency and native baseline comparison: **PASS**.
- Published, independently signer-verified GitHub Release: **NOT RUN**, owner merge/release approvals outstanding.
- Actual unaided independent developer completion and measured user value: **NOT RUN**, external contact and public release not authorized.
- Commercial demand / multi-repository paid requirement: **UNKNOWN**. Do not build hosted Teams based on this run.

R22 end-to-end technical rehearsal is **COMPLETED**; full First Real Product Value outcome **PARTIAL / BLOCKED at the owner release and external-user gate**. Whole-project percentage status remains Functional UNKNOWN (Δ UNKNOWN), Integrated E2E UNKNOWN (Δ UNKNOWN), Production readiness UNKNOWN (Δ UNKNOWN).
