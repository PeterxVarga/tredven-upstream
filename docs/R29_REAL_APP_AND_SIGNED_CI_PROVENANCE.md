# R29 — Real public API/worker upgrade E2E and signed CI provenance

**Date:** 2026-11-22. **Status:** R29 local technical vertical completed; actual GitHub-hosted signed CI unrun. Overall Tredven Upstream PARTIAL. This is a read-only/review-only development lane, not a live upgrade.

## End-to-end goal and ROI

Tredven Upstream remains a Rust program, but the affected application need not be Rust. The full desired user path: map integrations across systems → test the selected upstream version with actual services and their data → verify safe data migration and rollback → prove test provenance → owner-authorized one-action upgrade through existing software delivery providers.

ROI options considered: (1) keep simulating client SQL (cheap but no app value); (2) build a new privileged orchestrator/crypto/scanner (high-cost, unsafe reuse); (3) use pinned public application source + official Postgres/Celery/Podman tools + existing GitHub/Sigstore verifier (chosen). No real production deployments were attempted.

## Tested public application

**Source:** https://github.com/paulohsz/FastAPI-Celery-Docker pinned exactly to commit 417de5b4c3e2741853944fbf97a9988de48d647d. Source downloaded into Git-ignored owner-private output, not committed or redistributed.

The app includes actual FastAPI HTTP endpoints and a Celery worker that creates messages in PostgreSQL. The project's original RabbitMQ integration did not run rootless on Fedora because its Erlang cookie was unreadable (EACCES). This test therefore used the same unchanged upstream app and worker **with a Redis 7 Celery transport instead**; RabbitMQ compatibility is not proven. The private test image used redis-py 6.1.0 + packaging 25.0 per the installed Kombu transport requirements. Nonroot source-copy import permissions were fixed only in the disposable test image context. Docker/Podman host settings were not altered.

**Real observed sequence (two separately executed local isolated runs):**
The initial private development driver completed in 55.962 seconds. The
exact versioned public R29 test driver was subsequently exercised with the
same pinned upstream application source in another fresh isolated runtime,
and completed in 57.495 seconds, again with 7/8 and BLOCKED. These are
real technical E2E observations, not a performance benchmark.

1. PostgreSQL 16 + Redis + actual FastAPI + actual Celery worker start on an isolated Podman network with no host ports. HTTP POST creates one message, HTTP POST queues a separate task which is consumed by the real worker and commits a second message. Exactly 2 DB messages.
2. Actual PostgreSQL 17 pg_dump client reads PostgreSQL 16. After stopping the old server, pg_restore loads a *new* PostgreSQL 17 volume. API and worker restart; two new direct/async messages are persisted. Exactly 4 DB messages.
3. Return to the untouched old PostgreSQL 16 volume and restart actual API/worker; only the original 2 messages remain. The candidate version's 2 post-cutover writes are LOST by this rollback path.
4. The existing Rust qualify-system gate validates 8 source/Compose/receipt-bound checks. API + worker functionality and migration pass 7 checks, but data-loss rollback fails one. Rust outputs BLOCKED, refuses even the private local candidate stage, and never authorizes a live upgrade.

Private local evidence: output/r29-real-fastapi-celery-db-migration-20261122/r29-local-real-app-evidence.json, r29-real-app-rust-gate.json, eight receipt-*.json, and a synthetic PostgreSQL dump. All dedicated test containers, network, and data volumes removed. No real user data.

**Limitations:** upstream source code tested on a private synthetic environment, with substitute Redis transport, not a user's real application, production topology, RabbitMQ or real customer data. Two local runs are not a controlled performance benchmark. Local receipts are UNATTESTED.

## New provenance and CI engineering

- scripts/r29_real_public_app_upgrade_e2e.py: reproducible isolated test driver, publicly sharable source references, no application source redistribution; test driver is Python glue but Tredven's policy engine remains Rust.
- scripts/r29_prepare_public_app_test.sh: pins the public source Git commit and builds a private nonroot test image from upstream code.
- scripts/r29_make_signed_ci_manifest.py: on the exact reviewed owner-dispatched main workflow only, checks all 8 raw check outcomes and SHA256 digests, app source, Compose version, Rust BLOCKED verdict, workflow run ID/attempt/ref/source commit; outputs an UNSIGNED manifest.
- New Rust command: verify-system-ci --manifest FILE --evidence-dir DIR --policy POLICY.json. It first validates exact source/8 raw receipt/report/Rust decision hashes, then delegates actual cryptographic verification to the pre-existing official GitHub CLI/Sigstore attestation verifier and checks the exact GitHub workflow run URI. Even genuine provenance can only yield VERIFIED_CI_CLAIM with underlying upgrade BLOCKED. Production and one-click authority remain false.
- .github/workflows/r29-manual-real-app-ci.yml: GitHub-hosted Ubuntu 24.04, owner-only workflow_dispatch on reviewed main, pinned upstream action SHAs, attestation over the exact manifest, 7-day artifact upload of synthetic receipts. No automatic push/PR trigger, merge, deployment or release.

**Evidence levels clearly separated:**

1. Real isolated app E2E on Fedora: **PASS, 7 safe checks + 1 rollback data-loss failure**.
2. R29 Rust verifier tested with the original real local report bytes and a locally SIMULATED GitHub workflow envelope: all source/hash bindings matched, but no signing bundle exists, thus BLOCKED, not verified.
3. Deliberately changed raw rollback receipt: Rust refused before cryptographic verification, signed-manifest claim did NOT match. Five offline Python producer tests check wrong owner/ref/commit, tampered receipts and incorrect safe-rollbacks, plus Rust verifier tests.
4. GitHub-hosted actual attestation and successful hosted E2E: **UNKNOWN / NOT RUN**. A static workflow lint or simulated CI environment is not a hosted proof. GitHub artifact attestations are verifiable signed provenance statements about workflow-produced subjects; see https://docs.github.com/en/actions/concepts/security/artifact-attestations .

## Reproduction

The owner may run these only on an isolated Linux rootless-Podman environment with public image network and permission to create **new** disposable containers/volumes. The test never uses live credentials or existing data.

~~~bash
bash scripts/r29_prepare_public_app_test.sh
export TREDVEN_R29_RUST_CLI=/absolute/path/to/qualified/tredven-upstream
python3 -I -B scripts/r29_real_public_app_upgrade_e2e.py --output-name r29-local-unique
~~~

The actual successful Fedora execution used the same logic from a private copy with a different output directory, and an already-built test image. The reviewed source wrapper and hosted runner behavior must be independently requalified; do not infer that a CI YAML alone proves a hosted run.

## Roadmap and owner gates

No merge, workflow dispatch, public release, external user outreach or production deployment performed under this R29 scope. PR #6 (R26) → #7 (R27) → #8 (R28) → new R29 Draft must be separately reviewed and owner-approved in dependency order. A *separate* manual GitHub Actions dispatch is then needed for actual signed CI provenance.

The next highest ROI after hosted proof is **write-safe cutover**: freeze and drain queues and API writes, obtain a final migration checkpoint, test the candidate, and either reconcile candidate writes during rollback or fail closed. This is the actual remaining obstacle to the user's requested one-click safe upgrade.

Full project status: PARTIAL. Functional readiness UNKNOWN (Δ UNKNOWN), integrated E2E UNKNOWN (Δ UNKNOWN), production readiness UNKNOWN (Δ UNKNOWN); no reproducible project-wide acceptance denominator.
