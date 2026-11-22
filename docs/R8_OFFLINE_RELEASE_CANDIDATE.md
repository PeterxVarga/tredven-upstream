# R8 — Offline Rust release candidate and byte-integrity verification

Date: 2026-11-22. Branch: `feat/offline-local-release-candidate-r8-20261122`, parent R7 commit `d95637276886cf57a415fe46f7301dffbab1e75a`.

## Decision and actual user capability

R8 makes a **local, read-only-to-source, no-publication Rust release candidate** from a clean, exact Git commit, pinned Cargo.lock and pinned rust-toolchain.toml. It runs all local checks, compiles the Rust CLI, verifies the Cargo source package, builds a deterministically-metadata-normalized Linux .tar.gz containing the CLI+LICENSE+README, writes SHA256SUMS and a structured manifest, then byte-verifies them before declaring a local candidate. It does NOT publish, sign, attest, send, merge or deploy anything. The separate Rust CLI from R7 is unchanged.

**ROI challenger before action:** (A) write a homebrew Sigstore certificate/DSSE verifier: reject, security risk, unnecessary duplicate; (B) find an existing signed Trivy/OSV report for this exact project: unavailable in its public R7 branch (no release/workflow/attested scanner artifact); (C) create a GitHub Actions workflow that automatically publishes a release: reject, action authority and external execution not approved; (D) selected: deterministic local release-candidate preparation and hostile-file checks, requiring no secrets, service, network or new dependencies. The official GitHub/Sigstore verifier can be integrated **later**, with a real independently signed report or release artifact and explicit release permission.

References: [GitHub artifact-attestation overview](https://docs.github.com/en/actions/concepts/security/artifact-attestations), [GitHub verify offline](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline), [Sigstore Cosign verification](https://docs.sigstore.dev/cosign/verifying/verify/). SHA256SUMS and self-authored JSON are **not a signature**.

## Commands and explicit boundaries

Requirements: Python 3.11+ for standard-library tomllib, existing pinned Rust 1.100.0 with cached dependencies and Git. On the owner Fedora, Rust toolchain is installed in a preexisting user-owned external toolchain directory; ensure rustc/cargo are on PATH with correct RUSTUP_HOME and CARGO_HOME. No new toolchain or infrastructure is downloaded.

```bash
cd /path/to/tredven-upstream
python3 -I -B scripts/test_release_candidate.py
python3 -I -B scripts/release_candidate.py build --out output/r8-local-candidate
python3 -I -B scripts/release_candidate.py verify --dir output/r8-local-candidate
```

**Build requirements:** fully clean tracked+untracked Git worktree, exact 40-character HEAD commit, Cargo.lock, pinned rust-toolchain.toml version, no override CARGO_BUILD_TARGET/RUSTFLAGS, default local Linux host triple, and a new output directory directly below ignored `output/`. Builds use Cargo `--locked --offline`, SOURCE_DATE_EPOCH=0, Rustfmt, strict Clippy, every existing Rust test, optimized cargo build and `cargo package --offline --locked`. No network or crates.io upload.

**Files:** platform-qualified `tredven-upstream-vVERSION-TARGET.tar.gz` with normalized owner/time metadata, Cargo `.crate` source archive, `manifest.json`, and `SHA256SUMS`. The manifest records the Git commit, Cargo/rustc version, host target, source-archive sha256, executable sha256 and binary archive sha256. The tar.gz and source .crate are locally generated; the binary **has only been executed on Fedora** and is not independently tested across other distributions or CPU architectures.

**Verification:** all four files must be regular, non-symlink, size-bounded and the exact allowed set; SHA256SUMS must cover exactly the archive, crate and manifest. The manifest self-describes *no signature, no publisher verification, no scanner attestation, no production readiness, no publication authorization*. The archive is read as a bounded tar stream, all three member paths/metadata validated and the contained binary SHA256 compared to the manifest. Mutation, unexpected files, symlinks, forged publication flags and invalid checksum sets are rejected. The verifier is **not** a trust root: an adversary can replace all files and matching SHA256SUMS. A verified RC only means **local internal byte coherence**, not authenticity, remote publisher identity or safe deployment.

**Failure safety:** `build` refuses to overwrite an existing output candidate, requires a clean Git commit, writes to an owner-local staging folder and renames only after verification. Failed staging folders may remain for inspection, never be mistaken for final candidates. Only one local target triple is built. No GitHub Actions workflow is added or triggered.

## Qualification and value falsification

- R7 Rust CLI baseline tests: **108/108 PASS** (synthetic/Git-local, no actual Trivy/OSV execution).
- R8 synthetic release packaging integrity tests: valid self-check, identical bytes producing identical local archives, archive/`.crate` tampering, checksum/file scope errors, fabricated publication approval, symlink input and directory, CLI local-success and fail-closed exit codes.
- The build and verify of a **clean committed R8 source** must be executed before claiming a produced release candidate. Repeat builds on identical source/toolchain can test same-host archive checksum equality; do not claim cross-machine bit-for-bit reproducibility without separate environments.
- Main Git branch, existing R7 branch and any private Tredven worktrees stay unchanged. Output stays under locally ignored output/ and is **not committed or publicly released**.

**Not a confirmed product differentiator:** Cargo package already validates source crates, GitHub Actions builds binaries, and GitHub/Sigstore can attest real build artifacts. R8 intentionally reuses those existing tools and provides only a bounded local, self-service packaging entrypoint. Its incremental ROI is lower developer friction and a consistent receipt, not a demonstrated customer-saving or paid demand.

## Full project status and next best ROI

R8 local-release slice: **COMPLETED only when original clean source builds and tamper tests pass**. Full functional readiness **UNKNOWN (Δ UNKNOWN; no total feature denominator)**; integrated E2E **UNKNOWN (Δ UNKNOWN; no real scanner or signed origin)**; production readiness **UNKNOWN (Δ UNKNOWN; no approved release or external platform qualification)**. Next best ROI after verified candidate: inspect real externally produced signed artifacts and reuse `gh attestation verify`/`cosign verify-blob` under an exact issuer/repository policy, rather than implementing new cryptography. The user explicitly deferred testing the private Tredven application.
