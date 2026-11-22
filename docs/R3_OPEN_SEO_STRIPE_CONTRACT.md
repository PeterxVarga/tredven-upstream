# R3 — Source-pinned OpenSEO FK migration preflight

**Date:** 2026-11-22
**Public development branch:** `feat/open-seo-stripe-migration-contract-r3-20261122`
**Status:** source/fixture qualification complete, no application runtime or database migration exercised.

## Decision and user-visible capability

A narrow, source-bound Rust rule validates the **specific** OpenSEO PostgreSQL Drizzle migration `0049_stripe_projects_provider.sql` introduced in `v0.1.31` against the schema snapshot committed in `v0.1.27`.

The rule checks that the migration declares two new Stripe-projects tables and exactly four foreign-key references to `public.user(id)` / `public.organization(id)`; each referenced parent column in the baseline Drizzle snapshot must be of type `text`, `primaryKey: true`, `notNull: true`.

**Static preconditions matched in the original upstream Git source.** If a supplied schema fixture omits a required parent or has an incompatible id type, the result is **BLOCKED for the inspected snapshot**, not an assertion that any real database is missing it. If the source schema matches, the result remains **REVIEW**, never READY, because a running database and rollback were not tested. All action authorizations are always false.

## Exact original public source provenance (local Git, no remote attestation claim)

Public upstream: <https://github.com/every-app/open-seo>.

| Evidence | Exact, verified in local official-source checkout |
| --- | --- |
| Baseline tag | `v0.1.27`, commit `4fa42c879fd26657aec3472dcf44f08226816df3` |
| Candidate tag | `v0.1.31`, commit `0cc2f479a59acdbdd8a3e4d5c6e5c15493340b7c` |
| Candidate migration | `drizzle/pg/0049_stripe_projects_provider.sql`; Git blob `e0f8b57738a148e219c732cb7bd54cedeecc19d9` |
| Baseline schema snapshot | `drizzle/pg/meta/0046_snapshot.json`; Git blob `30515f76ca7538af57185b612b29f3de2d46e1bb` |
| Candidate migration journal | `drizzle/pg/meta/_journal.json`, contains `0049_stripe_projects_provider` as an actual migration sequence entry |

The Rust profile requires exactly these tag/commit and object pairs. It also checks expected statement fragments and the number of foreign-key references; it is **not a general SQL parser**. If these pins differ, it rejects the request rather than reusing stale evidence.

These are locally observed Git IDs from an original public source, **not cryptographic publisher identity attestation**. Source files are never executed and there is no production database connection.

## How to reproduce

Obtain a **local, read-only clone or disposable checkout** of the public repository containing both tags and run the new Rust CLI from this repo:

```bash
cargo test --locked --all-targets

cargo run --locked -- inspect-contract \
  --repo /ABSOLUTE/PATH/TO/open-seo-local-checkout \
  --project open-seo \
  --profile open-seo-v0.1.31-stripe-projects-0049 \
  --format markdown
```

**Observed:** `REVIEW`, all two parent-column requirements `MATCHED_SNAPSHOT`, source snapshot origin `BASELINE_GIT_SOURCE_SNAPSHOT_REMOTE_UNATTESTED`, `real_database_checked=false`, `sql_migration_executed=false`, `rollback_executed=false`, `production_ready=false`.

Synthetic failure demonstrations using this public repository's minimal **fake** Drizzle snapshots (not real deployment evidence):

```bash
cargo run --locked -- inspect-contract \
  --repo /ABSOLUTE/PATH/TO/open-seo-local-checkout \
  --project open-seo \
  --profile open-seo-v0.1.31-stripe-projects-0049 \
  --schema-snapshot fixtures/open-seo-0049-schema-synthetic-missing-organization.json

cargo run --locked -- inspect-contract \
  --repo /ABSOLUTE/PATH/TO/open-seo-local-checkout \
  --project open-seo \
  --profile open-seo-v0.1.31-stripe-projects-0049 \
  --schema-snapshot fixtures/open-seo-0049-schema-synthetic-wrong-id-type.json
```

**Observed:** both synthetic negative cases `BLOCKED`, exit code 2, `CALLER_SUPPLIED_SCHEMA_UNVERIFIED` and `real_database_checked=false`. The synthetic pass fixture returns `REVIEW`. A missing table in an **unverified, incomplete custom snapshot** is not proof that the live database lacks the table; the CLI accordingly labels the snapshot origin explicitly. Do not export an internal production schema into public fixtures.

## Security, constraints, and evidence levels

- Strict read-only existing local Git objects, with source blob/commit pins; no cloning/fetching, shell interpretation, untrusted hooks, SQL execution, DB connection, file write into source, credentials, provider write, app patch, sending, merge or deployment.
- Synthetic tests operate on in-memory/artificial schemas. Real original-source verification uses public upstream Git objects only. Neither constitutes an end-to-end upgrade of OpenSEO or any hosted MCP service.
- Existing Drizzle migrations themselves already enforce foreign-key dependencies at application time. **The improvement being tested is earlier, version-specific, human-readable preflight**, not novel database semantics or guaranteed business savings.
- `rust-anything` is a candidate methodology but was not used to replay the privileged private Python/Node system. No full Rust rewrite, network source identity proof, secure sandbox on untrusted local Git config, or production rollout claimed.
- No manual paid provider queries, real customer records, PII, OAuth tokens, external emails or X publication.

## ROI Challenger (before next work)

1. Build a broad generic SQL parser, database controller or automatic migrator now — **reject**: likely worse ROI, major blast radius, false confidence and vendor-native Drizzle already validates migrations at execution.
2. Continue mechanically rewriting every old Python/Node adapter to Rust — **defer**: language parity does not itself create preflight differentiation; only move portions required for validated user flows.
3. **Selected R3:** source-pinned *one migration* foreign-key parent contract, fake positive/failing cases, conservative report, no new provider authority. Demonstrates a verified safety question earlier than executing the migration.
4. **Next better ROI challenger:** check the native Drizzle migration workflow or existing CI can deliver the same non-destructive warning with negligible setup. If it can, stop expanding this as a commercial feature. If not, a second meaningful release compatibility test with a repeat maintainer may justify an extensible rule-pack format.

## Acceptance proof and remaining gates

- **Unit/CLI:** 20 Rust unit + 6 existing CLI + 10 disposable Git CLI tests = **36/36 PASS**. Rustfmt and strict Clippy PASS, Fedora Rust 1.100.0.
- **Actual original public Git source:** exact migration SQL blob and baseline schema blob resolved, both parent FK column contracts matched; report REVIEW / no release authority.
- **Negative:** synthetic missing parent, wrong type => BLOCKED exit 2; synthetic pass => REVIEW exit 0.
- **Pinned false promotion:** wrong profile and fake same-named tags with mismatched commits rejected by CLI test.
- **NOT DONE:** actual PostgreSQL migration, database lock/data behavior, backup/restore, deployed OpenSEO MCP/schema contract, tests against real self-hosted installation, paid buyer acceptance, commercial funnel proof.
- Product full functional **UNKNOWN (Δ UNKNOWN)**: no total product denominator. Integrated real E2E **UNKNOWN (Δ UNKNOWN)**: no tested running application upgrade. Production readiness **UNKNOWN (Δ UNKNOWN)**: no approved live data or deployment. Narrow R3 static preflight slice **COMPLETE**, overall OSS/paid SaaS **PARTIAL/HOLD**.

**Next best ROI:** measure incremental failure-prevention value vs native Drizzle/CI on this precise release (or directly implement a small reusable rule interface if and only if real operators benefit), not another dashboard or generalized rewrite.
