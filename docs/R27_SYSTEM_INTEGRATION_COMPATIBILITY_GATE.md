# R27 — System-aware upstream upgrade qualification (first vertical)

**Date:** 2026-11-22. **Status:** local, code-reviewed-in-Draft only; not merged or released. **Core objective:** Tredven Upstream is an **upstream software / service upgrade safety assistant**, implemented in Rust, **not** merely a dependency vulnerability scanner and **not** restricted to Rust user projects.

## End-state product (not yet delivered)

The user selects an installed tool, runtime, database, service or OSS component and its desired upstream version. Tredven should discover which other systems communicate with it (deployment config, service catalog, APIs, databases, queues, auth, observability and runtime traces); assess source and runtime compatibility, data migration and rollback; execute appropriately isolated integration tests; then show **one-click upgrade** only after complete, independent, source-bound acceptance and explicit owner approval. Changes should be applied via existing updater/CI/deployment providers rather than a new generic privileged orchestrator. The user should be able to roll back where that is actually supported.

**Critical distinction:** passing isolated tests is not mathematical proof that production will work; missing integration coverage remains **UNKNOWN**, and a passed local fixture never becomes owner permission to merge or deploy. A generic production one-click upgrade with no environment knowledge is unsafe.

## ROI Challenger (before implementation)

1. **Continue dependency-only R26**: strong source scanner parity but fails the stated service impact / compatibility / upgrade goal. Rejected as primary direction.
2. **Build full proprietary scanning, orchestration and upgrade engine**: duplicates mature OSS, creates a privileged parallel control plane, expensive and risky. Rejected.
3. **Reuse Compose / OpenTelemetry / Backstage / Testcontainers / Dagger / Renovate and add a small Rust source+evidence safety gate**: chosen. Static Compose links first, verified runtime integrations and owner-gated upgrader later.
4. **Direct untested image replacement**: fast and dangerous; real PostgreSQL counterexample below. Rejected.

Existing upstream OSS to reuse: [Compose service dependencies](https://docs.docker.com/reference/compose-file/services/), [OpenTelemetry Service Graph Connector](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/connector/servicegraphconnector), [Backstage system relations](https://backstage.io/docs/features/software-catalog/well-known-relations/), [Testcontainers](https://testcontainers.com/getting-started/), [Dagger](https://dagger.io/) and [Renovate](https://docs.renovatebot.com/key-concepts/automerge/). Do not fork their engines.

## Delivered local Rust vertical

New command:

```text
tredven-upstream qualify-system --config FILE [--stage-dir NEW_PRIVATE_DIRECTORY]
```

The Rust CLI reads two **named Git tags** without checking out or executing the project. It independently verifies each source-committed `compose.yaml`/`compose.yml`/`docker-compose.yaml`/`docker-compose.yml` is a bounded **ordinary Git blob**. Parsing uses the pure-Rust, MIT/Apache-2.0 `serde-yaml-rust2` library. It discovers Compose service nodes, `depends_on` and `links` edges, reverse/transitive downstream impacts, declared healthchecks and persistent volumes, and flags potential external connections by environment **key names only**. **Environment values and credentials are never emitted**.

For a proposed image change, it computes required **health + integration** checks for each directly/transitively affected service, plus target **rollback** and, for stateful/volume-bearing images, **data-migration** checks. It separately binds evidence receipts to the *candidate Git commit*, *candidate Compose file SHA-256*, exact service and check kind, and exact SHA-256 of the evidence JSON file. It refuses symlinks, missing files, invalid manifests, stale commits and claimed test success with zero tests. One checked **failure** yields `BLOCKED`; missing tests or unresolved dynamic/external topology yields `UNKNOWN`. Even an apparently complete set of un-attested locally supplied test receipts yields only **REVIEW**, never production-safe.

The local `--stage-dir` option, allowed **only when all declared requirements match and no unexpected Compose change is present**, copies the already-Git-proven candidate YAML and a review JSON into a **new private directory**. It does NOT edit the existing Git repository, push/merge a PR, start containers, deploy, touch production or perform a live one-click upgrade. It is a **one-action local review proposal**, not an actual upgrade.

**Coverage limitations:** This first vertical understands declared Docker Compose service relations only. It does not discover arbitrary outgoing HTTP connections, undocumented databases, shared networks, Kafka topics, separate applications, cross-repository dependencies or runtime traces. It cannot certify service interactions that have no declared relationship. The user-requested **general-purpose relationship discovery, real generic test executor and genuinely one-click live upgrade remain incomplete**.

## Real safety falsification: PostgreSQL 16 → 17 (not mocked)

A disposable Git repository was created with baseline tag `v16` and candidate tag `v17`. Its Compose services are `db` (Postgres image), `api` (depends on db), and `worker` (depends on api). Source commits:

- Baseline: `c57c0a85b4f1695284bc9e795669151acfeb54c2`
- Candidate: `638e273481e5d5d9f929f0581f4f037e003a5f91`
- Candidate Compose SHA-256: `b82cf7c59286d4beefdae3eb67333cf858d168aaba4ee45e3a3c75c393e0f65c`

In **rootless Podman, with a new disposable volume, no published ports, no network, no real user data and no production access**, Postgres 16 initialized a new database; a test table was created and read. After a controlled shutdown, the official, already cached Postgres 17 image was started **against the same persisted Postgres 16 data volume**. The actual process **exited with status 1**, with this observed fatal error:

```text
FATAL: database files are incompatible with server
DETAIL: The data directory was initialized by PostgreSQL version 16,
which is not compatible with this version 17.11.
```

The log was saved under ignored local evidence, SHA-256 `3d6e6d36e1e3d50134119393b85c32bd24ef249531ee0afb7460af8545e479a3`. All test containers and the disposable volume were destroyed after the run.

A source-bound, SHA-pinned `data-migration` failed receipt (JSON digest `296ffef82e257a5fb062a4787c3533a5d2948aa2a1633b0a9aa6db35668ca527`) was supplied to the **actual R27 Rust CLI**. The tool discovered affected `api`, `db` and `worker`, required **8** scoped health, integration, migration and rollback checks, returned **BLOCKED** and denied staging and live upgrade. This **demonstrates a real safety failure** without claiming that a correct PostgreSQL `pg_upgrade` or dump/restore procedure is impossible.

## Automated negative and isolated-staging tests

The `tests/system_upgrade_cli.rs` tests use disposable Git repositories; positive "all passed" fixtures are **synthetic user-supplied receipts**, not actual independent CI or proof of compatibility. They prove the program accepts exact SHA/commit/Compose-bound receipts and creates only local private stage files; missing, failed, corrupt or wrong-commit receipts block or mark unknown and never modify the original repository. Source-bound Git and the exact image-only normalized Compose equality guard prevent staging unrelated configuration changes.

## Remaining critical route to the real user-facing goal

1. **Broad and correctly scoped relationship inventory:** read-only adapters for Backstage, Compose/Kubernetes, APIs and OpenTelemetry runtime traces; explicit edge provenance, freshness, unknowns and scoped external dependency inventory. No credential/content leaks.
2. **Real isolated baseline-vs-candidate test executor:** reuse Testcontainers/Dagger/approved existing CI, run service-to-service and contract tests, migration on disposable copies of representative data, rollback tests; signed run/commit/environment receipts. A smoke test alone does not qualify data upgrades.
3. **Owner-controlled single-action upgrade:** reuse Renovate/PR updater, protected required checks, environment-specific staging and canary health, documented rollback; enable only for a fully qualified scope and explicit owner action. Never silently bypass review, run arbitrary scripts or deploy to live environments.
4. Independent human first-use task and relative user-time/decision quality evidence before commercial conclusions.

## Status and authorities

- **R27 scope:** real, source-bound Compose impact assessment and fail-closed compatibility-evidence qualification **COMPLETED locally** once tests pass; live one-click upgrade **NOT IMPLEMENTED**.
- **Full project:** PARTIAL. Functional readiness **UNKNOWN** (Δ UNKNOWN), integrated E2E **UNKNOWN** (Δ UNKNOWN), production-readiness **UNKNOWN** (Δ UNKNOWN); no reproducible project-wide denominator.
- **Security:** no production access, no secret emission, no GitHub PR merge, hosted workflow dispatch, release, external outreach or provider write authorized by this development scope. The public signed alpha `v0.1.0-alpha.1` is unaffected; R26 is still only Draft PR #6, and R27 is stacked separately.
