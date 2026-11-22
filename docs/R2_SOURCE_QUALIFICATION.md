# R2 — Local Git source qualification, strictly read-only

Date: 2026-11-22. Development scope: `feat/local-git-evidence-preflight-r2-20261122`.

## New usable capability

`tredven-upstream inspect-git --repo PATH --project ID --from TAG --to TAG [--format json|markdown]` operates exclusively on an **existing Git checkout** and installed local `git`. It resolves `refs/tags/TAG^{commit}` to exact local commit-object identifiers, classifies changed paths from a rename-disabled local Git diff, and emits a source-bound report with a bounded set of review candidates and all action authority **false**.

Git is run without a shell, global/system config, FSMonitor hooks, external diffs, textconv, Git lazy-fetch and optional Git locks. No `git fetch`, clone, checkout, provider API, network operation, production database, secret or deployment occurs in the CLI. Remote publisher identity, signed release verification and the deployed version remain **unattested**. A failure to read/validate input produces a nonzero error, **not** a fabricated COMPLETE report.

## Public-source reproducible example: every-app/open-seo

Public original source: <https://github.com/every-app/open-seo>.

Observed public tag identities in a credential-free Git HTTPS fetch to a private, local temporary source checkout:

| Git ref | Locally obtained commit |
| --- | --- |
| `refs/tags/v0.1.27` | `4fa42c879fd26657aec3472dcf44f08226816df3` |
| `refs/tags/v0.1.31` | `0cc2f479a59acdbdd8a3e4d5c6e5c15493340b7c` |

Local command (user must independently obtain a public clone with both tags; `inspect-git` itself never fetches):

```sh
cargo run --locked -- inspect-git \
  --repo /ABSOLUTE/PATH/TO/LOCAL/open-seo \
  --project open-seo \
  --from v0.1.27 --to v0.1.31 --format markdown
```

**Observed on this exact local public Git tree:**

- `REVIEW`, `evidence_origin=LOCAL_GIT_OBJECTS_REMOTE_UNATTESTED`.
- **514 changed file paths** with `--no-renames`. An independent default `git diff --name-only` gave 504 because rename detection groups some original paths. With the **same** `--no-renames` options the independent Git count matched 514.
- Classifier category totals: `API_OR_CONTRACT=103`, `DEPLOY_OR_DEPENDENCY=15`, `MIGRATION_OR_SCHEMA=34`, `OTHER=359`, `WORKER_OR_SEND_SURFACE=3`. Total = 514.
- Limited, **unverified review candidates** include `web/src/worker.ts` and `drizzle/pg/0047_ai_mode_engine.sql`. Source filenames, not independently established upgrade failures or database-migration outcomes.
- `runtime-tests=not_run`, `production_ready=false`, no send/merge/deploy/patch/release authority.
- The remote source's tag list was observed via public Git HTTPS separately, but the CLI does not cryptographically attest those origins. A malicious local repository can provide malicious tags; therefore the receipt is explicitly **not proof of official upstream authenticity**.

## Test/proof levels (do not conflate)

- **Original existing private Python gate (unchanged):** 21/21 source-gated offline regression baseline PASS on its exact existing branch/commit. Not an original app production E2E.
- **New Rust core/CLI:** 15 unit + 6 pre-existing CLI + 8 disposable Git integration tests = **29/29 PASS**; `cargo fmt --check` and `cargo clippy --locked --all-targets -- -D warnings` PASS, local Fedora. Git integration tests operate against generated **synthetic** commits, including missing tag, inconsistent ref, modified checkout, Git external-diff suppression and no-write contract.
- **Cross-language differential (real original source, but limited):** 514/514 public OpenSEO paths yielded the **same category result** in the original private Python classifier and new Rust CLI. No private Python code was published, and full cross-language adapter/report/hosted-runtime parity was **not tested**.
- **Actual public source path:** the OpenSEO two-tag Git object inspection is REAL read-only *local source evidence*; it is **not** a real running server upgrade, deployed application test, customer E2E, or evidence of willingness to pay.

## Security and product limitations

- This is a source-pinned *candidate triage* tool, not proof a database migration is safe or recoverable. It deliberately reports REVIEW for a changed tag pair even if some tests are declared passed.
- The full local changed-path list must be available and valid; CLI error/nonzero on oversized output, unsupported names or malformed references. Any untracked/dirty working tree content is excluded from the pinned two-tag comparison.
- The report may include filenames from the local clone; do not upload internal environment reports publicly.
- The current code uses caller-provided project label and tags. Only local Git object/tag resolution is observed, NOT the official remote release or deployed instance identity.
- No X announcement, public release tag, GitHub Actions workflow, paid SaaS, outreach, merge or deployment is authorized by these results.

## Critical remaining work / ROI Challenger

1. **Continue big rewrite of Python/Node adapters now:** poor ROI; original source/runtime authority gaps are still the critical risk.
2. **Build dashboard/billing now:** poor ROI; no external buyers or repeat application-specific value shown.
3. **Reuse local Git and native update PRs, then add one real upgrade-specific contract test:** **best next ROI**. Choose a single public, source-pinned migration/configuration requirement that can be independently checked; compare whether Renovate plus current tests already provides the same evidence before implementing new hosted infrastructure.
4. **Remote publisher verification:** important next provenance layer if real operators use the tool, but it does not by itself demonstrate a differentiation from Renovate. It remains necessary before any verified upstream identity/fully managed service claim.

**Status:** R2 local source qualification COMPLETE, entire Rust adapter migration PARTIAL. Functional product / integrated E2E / production readiness remain UNKNOWN (Δ UNKNOWN) for lack of a reproducible whole-product denominator and no running-system or paid-buyer proof.
