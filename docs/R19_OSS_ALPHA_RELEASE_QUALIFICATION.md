# R19 — OSS Alpha Release Qualification (owner-gated)

Date: 2026-11-22. Canonical repo: `PeterxVarga/tredven-upstream`. This work is on an isolated local `feat/r19-portable-alpha-review-20261122` branch descending from verified R18 `a1e232375f5be70cdf978026b251138fbc705c9c`.

## User-facing goal and ROI challenge

Get from a local read-only Rust dependency-review prototype toward a distributable OSS alpha **without** expanding the scanner, billing, cloud infrastructure or privileged agent runtime. The end-to-end capability is: standalone Linux CLI archive -> independently checked bytes -> run a source-bound `fd` v10.4.2 to v10.5.2 scan with explicit public OSV consent -> actionable `REVIEW` report. For true external adoption an unprepared outsider must later run this flow without us.

Options: (A) immediately merge the existing large PR and publish a release (not authorized and no external platform evidence); (B) add more scanner features/paid Teams backend (no proven adoption benefit); (C) use existing R12/R18 packaging, qualify Linux portability and exact third-party notices, then prepare a **stacked draft** PR for reviewer-only inspection (selected). The user retains separate merge, public release, outbound contact and deployment gates.

## Canonical version and scope

- Primary existing GitHub draft PR #1: baseline `main` -> `feat/r14-manual-ci-owner-qualification-20261122`, current PR head `5ad21855d9bbbfcb33625ca6d5af37017c22a26d`. This PR is ~55 files and unmerged; it is not enlarged during R19.
- R19 branch extends R16 public real-data source matching, reused R12 licensing, R17 configless first-use, R18 explicit SHA-pinned OSV downloader/cache, plus R19 *optional* static musl binary release-candidate path. No cloud permissions or workflows are added.
- Stacked PR base should be `feat/r14-manual-ci-owner-qualification-20261122`, rather than `main`, to avoid duplicate changes and let the smaller feature/release changes be reviewed separately. No automatic merges, no workflow dispatch, no GitHub Release.

## Linux portability falsification

- Previous Fedora-built GNU R18 binary: linked to newer GNU libc, ELF requests `GLIBC_2.39`. Tested in a freshly started read-only rootless **Debian 12 slim** container with glibc **2.36**. `--help` **exited 0** but loader emitted a weak-version warning. Do not claim the GNU binary universally fails on Debian 12.
- After obtaining Rust's officially supported `x86_64-unknown-linux-musl` target for pinned Rust 1.100.0, an **unchanged Tredven source** compiled with Rust's bundled `rust-lld` linker as an **ELF static PIE**, reported `statically linked` with no interpreter/DT_NEEDED. The same Debian 12 container ran its `--help` with **exit 0** and no GLIBC warning.
- The optional `--portable-musl` builder requires the pinned target standard library and linker, and uses `readelf` to enforce no ELF interpreter or DT_NEEDED; no unrestricted `RUSTFLAGS`, unknown linker or automatic downloading inside the offline build.
- The default GNU build remains unchanged and supported; this is **not** a claim of universal Linux distro compatibility, just demonstrated source/target portability.

## Runtime and crate licenses

- `scripts/release_candidate.py` already reads upstream exact `Cargo.lock`/Cargo metadata and embeds the complete 21 external registry-crate notice files in `THIRD_PARTY_NOTICES.txt`; R19 preserves it.
- The musl executable statically links Rust runtime and musl C runtime pieces. The portable-mode archive additionally includes **the exact pinned Rust 1.100.0 toolchain** `share/doc/rust/COPYRIGHT-library.html` under `RUST_RUNTIME_NOTICES.html`. It contains a section crediting musl, with the relevant MIT license text, in addition to the Rust standard library's complete third-party notices.
- The extra runtime notice is required only in the musl archive, included in the archive's manifest SHA-256 and checked even when outer tar/checksums are rehashed. An old GNU archive remains verifiable. The archive does not bundle OSV-Scanner, GitHub CLI or unrelated proprietary binaries.
- No claim of legal sufficiency is made by engineering checks; public redistribution needs owner approval and a last legal/attribution review.

## Reproducible acceptance

- Existing `R18` real reference: public `sharkdp/fd` Git tags v10.4.2 (7027d45303b412be6fa9c09d689cc6276748fb38) and v10.5.2 (b2a287b3993768e0ec52f0852916917f23fb2a38), OSV-Scanner 2.7.1 pinned official Linux amd64 `fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8`, with three old and zero new advisory occurrences. The delta is informational REVIEW.
- Built source requires **clean working tree** before release-candidate packaging. Package verification checks `manifest.json`, `SHA256SUMS`, trusted runtime notices, exact four/five permitted tar members (per target), ELF loader properties and no implicit publication rights.
- Additional tests: static/musl target release is possible; missing/wrong runtime notices fail closed, rehashed tampering fails; host GNU packaging continues to pass. Full Rust regression and Python licensing tests to be checked again on the final committed source.
- On the pinned GNU host: `python3 -I -B scripts/release_candidate.py build --out /.../output/unique --portable-musl`, then `verify --dir` and run extracted `bin/tredven-upstream review-local ... --install-pinned-osv --allow-public-osv-network` on an independent public Git repository.

## Real output & risk notes

- Exact archived musl artifact SHA, source commit and test counts are recorded by the final clean-source output manifest, SHA256SUMS and release qualification transcript, not assumed from a pre-build estimate.
- Evidence hierarchy: synthetic local tests / genuine public Git + OSV API local E2E / Debian 12 offline container smoke / hosted signed GitHub Action / public signed binary release / independent human test are **distinct**. The latter three are not qualified by earlier local PASS.
- Current browser/hosting production behavior: UNKNOWN; `main` unchanged; no Actions runs yet; no GitHub release.

## Project status

FULL PROJECT: PARTIAL. Functional readiness UNKNOWN (Δ UNKNOWN), integrated E2E readiness UNKNOWN (Δ UNKNOWN), production readiness UNKNOWN (Δ UNKNOWN). No reproducible whole-project denominator exists. The targeted R19 acceptance gates can pass individually, but they are not whole-product production evidence.

Next best ROI after local acceptance: stacked Draft PR for human review; owner-authorized merge, then official signed artifact release and first independent developer time-to-decision benchmark. No new billing backend until actual collaborative workflow demand is observed.
