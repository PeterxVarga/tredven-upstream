# R4 — Drizzle-native counterfactual: does the R3 SQL preflight save unique operator work?

**Date:** 2026-11-22
**Scope:** the exact OpenSEO v0.1.27 → v0.1.31 `0049_stripe_projects_provider.sql` foreign-key-parent check, **not** the whole Tredven Upstream product or prior R2 Git source adapter.
**Decision:** **FALSIFIED_AS_STANDALONE_COMMERCIAL_DIFFERENTIATOR**; **KEEP_AS_INTERNAL_OSS_TEST_CASE**. No SaaS feature or generic SQL engine expansion justified by these facts.

## 1. Exact counterfactual and source provenance

Primary upstream Git source: [every-app/open-seo](https://github.com/every-app/open-seo), pinned `v0.1.31` commit `0cc2f479a59acdbdd8a3e4d5c6e5c15493340b7c`.

- [CI](https://github.com/every-app/open-seo/blob/v0.1.31/.github/workflows/ci.yml) runs `pnpm ci:check`, `pnpm test:ci`, build and other checks. In the pinned job definition, **no dedicated static Drizzle FK parent-snapshot preflight** and no `drizzle-kit check` or `db:migrate:pg` step appears.
- [package.json](https://github.com/every-app/open-seo/blob/v0.1.31/package.json) includes `db:migrate:pg` = `drizzle-kit migrate --config drizzle/pg.config.ts`, alongside `drizzle-kit ^0.31.10`.
- [production deploy](https://github.com/every-app/open-seo/blob/v0.1.31/.github/workflows/deploy-production.yml) performs **Migrate production Postgres** via `pnpm db:migrate:pg` before deploying Workers. Do NOT run this workflow, use credentials, or infer result.
- [self-host deploy preflight](https://github.com/every-app/open-seo/blob/v0.1.31/scripts/selfhost-deploy-preflight.mjs) targets Node/env/Cloudflare login and permissions; it contains no check for these precise Drizzle FK parent table columns.
- [official Drizzle `check` docs](https://orm.drizzle.team/docs/drizzle-kit-check) describe **generated migration-history consistency**, not a read-only check that a live DB matches the schema or the specific foreign-key parent invariant.
- [official Drizzle `migrate` docs](https://orm.drizzle.team/docs/drizzle-kit-migrate) explicitly require a DB connection to apply migrations and persist migration state.

**Proof levels:** source file inspection of pinned upstream tag and official documentation **YES**. Execution of real Drizzle `check` using OpenSEO's exact installed dependency **NOT RUN**. Actual PostgreSQL migration or rollback, current hosted server readback, future Drizzle v1 semantics **NOT RUN / NOT INFERRED**.

## 2. Independent native-stack replacement tested locally

A deliberately simple, **non-product, read-only Node.js 24** script was authored in `research/r4-native-counterfactual/independent-node-baseline.mjs`, **43 lines, no external npm packages**. It reads two named local Git tag/commit identities and their exact pinned migration + baseline snapshot blob hashes using the installed Git binary, checks key migration SQL fragments and the baseline Drizzle JSON structure, then emits a minimal `REVIEW` or `BLOCKED` decision.

This is **not** `drizzle-kit check`, **not** a fully hardened or production-ready replacement, and **not** a claim of security, output/schema compatibility, auto-upgrades, or performance parity. It is an **existence proof that the narrow business-relevant classification can be expressed very cheaply within the repo's existing Node toolchain**. It leverages the exact same source pins and synthetic fixtures, but is an independent implementation.

### Executed result (local, isolated, 2026-11-22)

| Evidence case | Rust R3 / status | Node native-stack counterfactual / status |
|---|---|---|
| Original public OpenSEO v0.1.27 schema and fixed 0049 SQL | REVIEW / exit 0 | REVIEW / exit 0 |
| Synthetic complete baseline schema | REVIEW / exit 0 | REVIEW / exit 0 |
| Synthetic missing `public.organization(id)` | BLOCKED / exit 2 | BLOCKED / exit 2 |
| Synthetic incompatible `public.user(id)` type | BLOCKED / exit 2 | BLOCKED / exit 2 |

**Functional counterfactual: 4/4 matching statuses/exit codes**, as personally observed from each CLI run. Node script explicitly reports `databaseChecked=false`, `sqlExecuted=false`, `approval=false`.

Rust R3 feature branch baseline remains **36/36 unit+CLI/Git integration tests PASS** on prior verified Fedora run. R4 **did not change Rust source or add independent product features**, and a test count is not evidence of buyer ROI.

### Reproduction

```bash
# On this public repo's R4 research branch, with a local clone of every-app/open-seo
# that contains the v0.1.27 and v0.1.31 tag objects.
REPO=/path/to/your/local/open-seo

node research/r4-native-counterfactual/independent-node-baseline.mjs "$REPO"

node research/r4-native-counterfactual/independent-node-baseline.mjs \
  "$REPO" fixtures/open-seo-0049-schema-synthetic-missing-organization.json
# returns BLOCKED with code 2, no database connection
```

The earlier R3 Rust command remains:

```bash
cargo run --locked -- inspect-contract --repo "$REPO" \
  --project open-seo --profile open-seo-v0.1.31-stripe-projects-0049
```

The repo source files are publicly inspectable. No JavaScript/NPM dependencies or hidden runtime services were added.

## 3. What value was and was not falsified?

**Observed gap in the pinned OpenSEO CI:** no explicit pre-migration static FK-schema check was found. The R3 preflight would surface the two parent contracts before invoking a database mutation. This is technically useful if the inspected source schema is complete and an operator values an extra warning.

**But:** Drizzle itself handles the migration DDL and DB constraints when `migrate` runs. The source's original baseline snapshot **already contains both required parent tables and text PK id columns**. No actual production failure from this version change was observed. An extremely small optional Node check provides equivalent classification on every selected fixture in the existing toolchain.

**Not established:** the new CLI finds an error an existing native check cannot cheaply find, real saved staff hours, reduced incidents, prevention of a real SQL failure, buyer's installed tools/maintenance budget, accepted paid price, release-safe E2E, or willingness to run the Rust CLI. The synthetic fail cases are **not** actual OpenSEO defects.

A narrow source snapshot check **cannot** prove that a deployed PostgreSQL instance was migrated to the same point: live history, schema drift, permissions, data-dependent constraints, lock duration, backup/restore and rollback remain UNKNOWN.

A separate narrow observation: the public release introduced `STRIPE_PROJECTS_SIGNING_SECRET`, but the app code treats it as an optional feature gate (absence yields 404 in the Stripe Projects handler); this is not automatically a breaking mandatory configuration requirement. Do not claim a paid migration failure on that basis.

## 4. ROI Challenger, including the adverse counterexample

| Real option | Evidence-based evaluation |
|---|---|
| Build generic Rust SQL analyzer, rule dashboard, managed alerts | Reject. Adds recurring support and claims without unique buyer proof. |
| Keep porting Python/Node mechanically | Defer. Rust portability has value, but converting a 43-line native equivalent is not a customer benefit by itself. |
| Add `drizzle-kit check` directly to upstream CI | Feasible incumbent counterfactual for migration-history integrity. **Not claimed to check this particular FK parent invariant.** Existing CI currently does not call it. Would require a separate controlled test against exact 0.31.10 version. |
| Add a small native Node check | **Best for this narrow OpenSEO task** if its actual operator wants the guard: 43-line third-party- and runtime-credential-free equivalent for the observed classification. Not hardening-complete. |
| Keep R3 as bounded Rust OSS source-pinned demonstration; seek a *non-native* recurring compatibility failure | **Best for Tredven Upstream overall:** retain internal usefulness, stop escalating this weak commercial wedge, look for truly residual post-Renovate/Drizzle/CI maintainer labor. |

**Falsification prompt:** If asked “sure this Rust rule is the next best ROI?” the answer is **NO**: a small existing-stack Node command can deliver the same four relevant decisions without an extra install. No external buyer has been shown to prefer a separate Rust binary for this rule. The portfolio Recycling project is not displaced by speculative X growth.

## 5. Final state and next proof

- R4 **research and counterfactual experiment COMPLETE**. New independent Node research script and report only; **no modifications to existing Rust CLI/authoritative source contract**.
- **Narrow commercial hypothesis REJECT / STOP_EXTENSION** for this one migration check. The broader OSS product and persistent internal Tredven value remain viable hypotheses independently, with external paying-customer evidence **HOLD / NOT_PROVEN**.
- No pub repo `main` merge, no release, deploy, source mutation, user/customer data, send, paid queries, or unauthorized owner actions.
- **Next truly higher ROI:** locate **one documented recurring upgrade problem in a Tredven-maintained self-hosted integration** that the installed incumbent and a short native script do not already address; demonstrate an actual prevented failure or repeatable time/cost reduction, then decide whether a generic Rust rule pack is warranted. If unavailable, keep the project on its already-working internal track; do not inflate scope.
- Whole-project functional readiness **UNKNOWN (Δ UNKNOWN; no reproducible denominator)**; integrated E2E **UNKNOWN (Δ UNKNOWN; no actual application upgrade/rollback)**; production readiness **UNKNOWN (Δ UNKNOWN; no approved deployment and real-user use)**.

**Status:** RESEARCH COMPLETED · COMMERCIAL SUB-HYPOTHESIS REJECTED · R3 RUST FEATURE RETAINED AS INTERNAL/OSS DEMO.
