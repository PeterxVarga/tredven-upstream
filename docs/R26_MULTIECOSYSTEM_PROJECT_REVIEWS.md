# R26 — Multi-ecosystem project upgrade reviews, Rust CLI

**Date:** 2026-11-22. Development branch `feat/r26-multiecosystem-local-review-20261122`, based on the published R25 main commit `61d1a12d88e822fdfa6ba652115cbf06132614df`.

## Product requirement

**The Tredven Upstream program is written in Rust; users' projects do NOT have to be written in Rust.** It is an ecosystem-agnostic, read-only *dependency upgrade risk review* composing existing OSS scanners, local Git object evidence and a conservative human decision. It is **not** a general-purpose source-code static analyzer, automatic fixer, runtime scanner or guarantee of safe production rollout.

## ROI Challenger and accepted vertical

- **Continue the Cargo.lock-only CLI:** keeps a working first public alpha but fails the explicit general-purpose product requirement, and narrows potential adoption unjustifiably. Rejected.
- **Author custom npm/pip/Go/Maven scanners:** duplicates Google's well-maintained OSV/SCALIBR parsing, introduces supply-chain and correctness risk and delays real product evaluation. Rejected.
- **Generalize the already deployed Rust + upstream OSV scanner pipeline:** reuses official v2.7.1, native Trivy/OSV report parsing, SHA pinning, source identity, risk decisions, evidence and conservative gates. Selected.
- **Full recursive all-lockfiles, polyglot monorepo support now:** stronger ultimate goal, but naive merging of heterogeneous scanner scopes can create false coverage and requires changing established fail-closed comparisons. Defer until justified; never claim an entire mixed repository was scanned from one selected lockfile.

## New user-facing capability

`review-local --repo DIR --from TAG --to TAG [--lockfile RELATIVE_PATH] --install-pinned-osv --allow-public-osv-network` now runs on a supported **root lockfile/manifest from any OSV ecosystem**, not just `Cargo.lock`. When exactly **one** root supported dependency file is present in the candidate Git tree, it is automatically selected; if none, or more than one, it fails closed and requests an explicit `--lockfile` argument. Explicit paths may be nested (for example, `services/api/poetry.lock` or `apps/web/package-lock.json`). The *same* selected path must be an ordinary Git blob in both Git-tag commits, no symlink/submodule; traversal, unknown names, absolute paths and unintended scanner downloads are rejected.

The program keeps the lockfile in a private scratch directory with the correct basename, reuses the exact same path for both OSV scans, compares only matching source scopes, and writes owner-private `baseline.<filename>` and `candidate.<filename>` when explicitly asked to save raw evidence. The review JSON includes `analyzed_lockfile`, and the Markdown report clearly states this is **one selected dependency file, NOT proof of whole-repository coverage**. The signed-CI receipt remains **Cargo.lock-specific**, separately, and is **not** claimed to work across other ecosystems.

**Boundaries:** OSV's `--no-resolve` analysis covers dependency versions present in selected files only. `pom.xml` and `requirements.txt` may contain ranges, editable or unpinned dependencies, so the resulting inventory is not necessarily the whole installed environment. No private lockfile, credentials or scanner telemetry are sent to a Tredven service. The OSV tool receives package metadata **only** with explicit public OSV network consent. Current direct Git blob cap is **2,000,000 bytes**; larger project files fail closed. Managed official scanner bootstrap remains Linux x86-64 only, with a manual exact-SHA scanner path supported elsewhere.

## Real public, non-Rust E2E evidence (not synthetic scanners)

Source object tag commits below were fetched **without checkout or project script execution**, then the locally compiled **Rust** development CLI scanned two real source-bound lockfile bytes using the pinned official OSV-Scanner v2.7.1, SHA256 `fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8`. Raw scanner JSON and original Git lockfile snapshots were saved locally; a second set of **six independent native OSV scans** verified the complete multiset of `(ecosystem, package, version, advisory id)` findings matched the Rust CLI's original scanner reports, not just their counts.

| Public upstream project | Source tags | Selected file | Scanner advisory occurrences baseline → candidate | New / resolved distinct delta occurrences | Conservative result |
| --- | --- | --- | --- | --- | --- |
| [axios/axios](https://github.com/axios/axios) | v1.7.7 → v1.7.8 | `package-lock.json` | **279 → 262** | 3 / 14 | **BLOCKED** |
| [stefanprodan/podinfo](https://github.com/stefanprodan/podinfo) | 6.8.0 → 6.9.0 | `go.mod` | **50 → 47** | 4 / 7 | **BLOCKED** |
| [encode/httpx](https://github.com/encode/httpx) | 0.27.1 → 0.27.2 | `requirements.txt` | **15 → 15** | 0 / 0 | **BLOCKED** |

Scanner advisory occurrence counts and delta finding identities have distinct counting semantics; **do not subtract the reported new/resolved unique deltas from raw occurrence totals** and falsely claim they must reconcile. All reports matched the exact selected Git lockfile hashes, confirmed comparable scanner scopes, and denied production readiness and release authority. The Python requirements manifest explicitly includes `-e .[...]` local-editable packages: scanning its resolved pinned lines does **not** prove full Python environment coverage. OSV database queries are time-sensitive. The public Git tag objects were not cryptographically publisher-attested.

An additional **synthetic Git monorepo with two exact real public Axios `package-lock.json` bytes** placed at `apps/web/package-lock.json` demonstrates nested explicit-path scanning with the same source hashes, actual native OSV findings and conservative verdict. It is **not** a fourth independent real upstream repository, merely an isolated nested-path regression.

## Negative and control evidence

Rust unit/integration tests enforce arbitrary path rejection, no implicit network, correct Git blob mode (symlinks are rejected), two-tag source byte binding, auto-detection from committed Git objects rather than the working tree, no unsupported/ambiguous auto-selection, nested paths and no cache creation if the selected file cannot qualify. The old Cargo.lock public-data cleanroom proof and signed release workflow remain unchanged. The actual R26 branch tests and native-parity receipt are under ignored `output/r26-public-nonrust-samples-20261122/` and are **not** published as source or uploaded with Draft PR assets.

## Publication status / ROI

**R26 is code and test evidence on an unmerged development branch.** The previously publicly released, GitHub/Sigstore-signed `v0.1.0-alpha.1` remains the older Cargo.lock-first implementation; it does **not** include R26 changes. Do not make a new Release or trigger the manual signing workflow without separate owner authorization. Draft PR review and local testing do not prove an external developer can use this new revision.

**Next highest ROI after authorization:** independently review and integrate R26, sign and publish a revised alpha only with separate owner approval, then have 2–3 independent developers cold-install it on different real technology stacks. If multiple real monorepos are blocked by needing several explicit scans, implement a bounded multi-lockfile evidence aggregator as the next vertical, with explicit partial-coverage semantics.

**Project status:** PARTIAL. Functional readiness **UNKNOWN (Δ UNKNOWN)**, integrated E2E **UNKNOWN (Δ UNKNOWN)**, production readiness **UNKNOWN (Δ UNKNOWN)** absent a reproducible project-wide denominator. Demonstrated public npm/Go/Python local scanner E2E is **not** hosted/signed R26 release or external user-value proof.
