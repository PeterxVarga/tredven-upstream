# R28 — Real isolated PostgreSQL 16→17 migration, client contracts, rollback and Rust gate

**Date:** 2026-11-22. **Scope:** Tredven Upstream's system-aware upgrade compatibility lane only. Local development branch stacked on R27 and R26 Draft PRs. This is NOT a production upgrade engine, hosted signing run, GitHub release, live rollout or commercial first-use trial.

## Decision and ROI Challenger

The target user journey is: discover a service's dependants → qualify the target upstream version → test old and new environments, data migration, client compatibility and recovery → offer a ONE-ACTION live upgrade only when the actual deployment environment is independently qualified and the owner authorizes it.

Three viable options were compared:

1. **Swap the PostgreSQL 16 container image for 17, keep its data volume:** rejected. R27 previously proved the actual Postgres 17 process exits with the fatal error `database files are incompatible with server`, not a safe upgrade.
2. **Use PostgreSQL `pg_upgrade` with both engine binaries and explicit compatibility settings:** real OSS alternative, potentially better for large datasets, but needs additional binary/extension/image layout integration, `pg_upgrade --check` and rollback qualification. Premature for a synthetic two-table first vertical.
3. **Use PostgreSQL's official `pg_dump -Fc` / `pg_restore` logical migration:** selected. Uses existing cached upstream tools, separate fresh destination data directory, preserves untouched original old-volume state and allows explicit verification of data/API/worker/rollback.

Official reference: https://www.postgresql.org/docs/17/upgrading.html . For PostgreSQL 17 and earlier the Docker Official Image stores PGDATA at `/var/lib/postgresql/data`; Postgres 18+ differs. The test intentionally targets 16→17 only.

## Executable full vertical

Source: `scripts/r28_disposable_postgres_upgrade.py` (test-only Python orchestration of existing Podman/psql/pg_dump/pg_restore, NOT the Tredven runtime). All business decision logic, Compose service graph evaluation and authorizing local candidate staging remain in the **Rust** `qualify-system` CLI.

Run only on a Fedora/Linux host with rootless Podman and the two previously-cached official Postgres image tags; no image pull:

```bash
# Build existing Rust R27 CLI (no GitHub dispatch/deployment)
cargo build --offline --locked
export TREDVEN_R28_RUST_CLI="$PWD/target/debug/tredven-upstream"

# Creates fresh ignored output/r28-* directory; refuses to overwrite
python3 -I -B scripts/r28_disposable_postgres_upgrade.py \
  --output-name r28-disposable-new-unique-name
```

The actual local developer environment uses a separate `CARGO_TARGET_DIR`; point the variable at the qualified binary there when appropriate. No CLI options accept existing Podman names, live data paths, external repositories, registry credentials or privileged access.

All SQL and Compose input data are explicitly synthetic, source-bound in a new local Git fixture with named `r28-16` and `r28-17` tags (only the selected database image reference changes). The actual execution:

1. Reject root execution, missing cached images or non-rootless Podman. Create exactly **two fresh, random-prefixed named volumes** and disposable database containers; never touch existing volumes, services or production data. No host ports; database container network mode `none`.
2. Initialize PostgreSQL 16 and test two actual PostgreSQL client containers, sharing **only the database's network namespace**, with simulated API/worker SQL contracts. Create orders and jobs with foreign key constraints and two rows each; capture a deterministic content fingerprint.
3. Run **PostgreSQL 17 `pg_dump -Fc` client against PostgreSQL 16**, save a 0600-permission local dump, stop the old database, then create a fresh PostgreSQL 17 volume and restore with `pg_restore --exit-on-error --no-owner --no-acl`.
4. Verify PostgreSQL 17 real TCP health; schema join, exact data fingerprint, separate API SQL read+transactional insert+ROLLBACK, and worker SQL read+transactional update+ROLLBACK. Check that these test writes left **no** persistent changes.
5. Stop PostgreSQL 17; restart PostgreSQL 16 on its **unchanged original volume** and verify original data fingerprint and client queries match. This proves rollback only for the specifically write-frozen synthetic case; it does **not** demonstrate lossless reverse migration after new-version production writes.
6. Generate **8 checked, source-/Compose-/raw-byte-SHA-bound local user-supplied receipts** for DB health, DB integration, migration, rollback, API health/integration and worker health/integration. The Rust R27 `qualify-system` qualifies all 8 and writes a local candidate review folder (verdict **REVIEW**, never permission to deploy). Deliberate migration failure receipt injection produces **BLOCKED** and refuses local candidate staging.
7. Verify all temporary database containers and named volumes have been removed. No global cleanup, `prune`, host firewall or root-service modification. Stored evidence remains under Git-ignored `output/`.

### Proven root cause of initial harness failure

The first run saw `FATAL: database system is shutting down` while restoring. The official PostgreSQL Docker entrypoint temporarily starts a **Unix-socket-only** PostgreSQL server to initialize `POSTGRES_DB`, then stops it before starting the final TCP-listening server. A local Unix-socket `pg_isready` produced a premature readiness signal. The corrected harness waits on **127.0.0.1 TCP**, preventing that concrete race. Original entrypoint `docker_temp_server_start()` config contains `-c listen_addresses=''` (verified against cached Postgres 17 image). The first run failed safely; newly allocated resources were cleaned. A dedicated offline regression test asserts the TCP readiness contract.

## Real result and private local evidence

Successful corrected run:
- Rootless Podman with cached PostgreSQL 16 and PostgreSQL 17, isolated synthetic data and no host ports
- **37.289 seconds** for the full exercised vertical including cleanup (single run, NOT a performance study)
- Baseline Git commit: `d00c9fcb3327e4e07ca679f90623b69b797cebbd`
- Candidate Git commit: `377942d9e3d87b20b76c5b7852226cbaed5f1708`
- All **8/8** required scoped checks observed
- Exact deterministic data fingerprint identical on 16, migrated 17 and restored 16: `06b2152ef1457c2bd9e3d62ca7e65e72`
- Rust decision: **REVIEW, local-only**, deliberately injected migration failure: **BLOCKED**
- All disposable database resources verified absent

Local receipt: `output/r28-tcp-ready-migration-rollback-20261122/r28-e2e-receipt.json`; source-bound test receipts and synthetic database dump in the same ignored, owner-private directory.

## Evidence limitations and next ROI

- The API and worker tests are **real, separate PostgreSQL client containers executing representative SQL**, **not** the user's real API/worker code, traffic or runtime instrumentation.
- Only one single database is migrated; logical dump/restore does not cover whole-cluster roles, all extensions, settings, external secrets or every application connection.
- The test uses Postgres `trust` authentication **only** in an isolated non-networked disposable sandbox, with no actual user secrets or production assets.
- Backup verification is based on a successful actual restore and deterministic SQL checks, not an independent external backup/restore service.
- Unattested local user-supplied test receipts are not independently signed CI provenance; even 8/8 can only yield Rust verdict `REVIEW`. No production claim or automatic live upgrade.
- The rollback returns to the old frozen state, and would discard any permanent writes made on Postgres 17 after cutover. Production-grade rollback needs planned write freeze, cutover, reconciliation and operator permission.
- The official Postgres and Podman engines are reused. Do not create a parallel privileged orchestration system.

**Next high-value E2E:** independently check a *real non-sensitive 3-service application’s* contract tests with a real test reporter bound to commit/environment; implement an owner-approved updater PR via existing Renovate/GitHub checks and isolated staging deployment only after completing service-graph coverage. Do not interpret tests or a local review folder as one-click live upgrade.

## Full project status

The **local R28 isolated Postgres migration/rollback E2E is COMPLETED**. Overall product is **PARTIAL**: full automatic integration discovery, signed test executor, safe owner-gated staging and one-click rollback remain incomplete. Whole-project functional %, integrated E2E %, production readiness %, and all percentage-point deltas **UNKNOWN** (no reproducible denominator).
