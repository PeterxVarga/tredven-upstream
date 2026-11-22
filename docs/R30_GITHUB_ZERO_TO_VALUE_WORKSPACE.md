# R30 — GitHub Zero-to-Value & Maintenance Workspace

**Scope:** Tredven Upstream only · **Date:** 2026-11-22 · **Status:** local GitHub CLI + loopback dashboard E2E **COMPLETED**, hosted GitHub App / scheduled monitoring / customer-grade E2E **NOT BUILT**.

## Decision and ROI Challenger

The desired product is a low-friction, all-in-one workflow: connect GitHub → see all **authorized** repositories → select those worth maintaining → inspect current dependency/CI/service context → investigate a particular upgrade PR using the same Rust decision engine → later attach independently verified integration and rollback evidence. The dashboard, CLI and a future MCP adapter must use one core.

Compared before coding:

1. **Another compatibility, signing or runtime test:** adds technical proof, but no first-user onboarding.
2. **Build the whole hosted GitHub App + auth + SaaS dashboard + scheduler + MCP now:** high privilege, complexity and unvalidated operating cost, and cannot be qualified without an installed GitHub App.
3. **Use the existing authorized GitHub CLI user session and GitHub REST APIs, one private Rust workspace model and a local, interactive dashboard:** selected; shortest proven end-to-end path, reusable as a provider abstraction for later GitHub App auth.
4. **Automated merge/deployment/rollback:** explicitly outside R30, not safe until real runtime and owner gates have been satisfied.

## Source and authorizations

- Parent branch: R29 `feat/r29-real-app-ci-provenance-gate-20261122`, commit `44d6eef16de40e33474e578c0ffcd7a2e1b4c698`.
- Existing GitHub authentication is provided **only by the locally installed, already-authenticated GitHub CLI**; the product never requests, prints or stores its token. No new scopes, OAuth consent or GitHub App installation was performed.
- `github-workspace discover` paginates GitHub `user/repos` for owner, collaborator and organization membership, up to 1000 entries; a partial/failing listing is **not** stored as a complete inventory. Each repository has a stable GitHub ID, authorized account ID, source reference and private/archived/fork status. Previously selected IDs are retained only when still returned by the same authenticated account. Removed entries are discarded on complete refresh.
- `github-workspace review` checks current account identity and repository API access *again* before reading the selected repository. It uses the GitHub REST commit/tree APIs to identify manifests, lockfiles and CI paths, plus GitHub's pull list, and optionally retrieves a specific PR and its commit compare. It never executes untrusted repository code. GitHub tree/PR truncation or unknown dependencies are reported as incomplete; missing is **not zero**.
- The existing Rust `inspect` core classifies **real changed files** from an exact GitHub PR compare, with original base/head commit IDs, a bounded path list and **UNKNOWN** test evidence. It does **not** manufacture cryptographic provenance, passing integration tests or live approval.
- Optional `github-workspace qualify` loads an owner-supplied *existing* R27/R29 `qualify-system` JSON configuration, reads only local Git tags/Compose and source-bound test receipts, and **requires the local repository remote origin AND both resolved Git commits to match the exact selected GitHub PR**. Failed origin or commit bindings refuse the association. No fresh runtime tests, local candidate staging, Github mutations or production approval are initiated.

## Actual first-user local E2E evidence

Using the owner-authorized Fedora 44 GitHub CLI login:

1. Authenticated, paginated discovery returned **46 accessible repositories**. Repository metadata was stored only under `output/r30-owner-private-github-e2e-20261122/workspace.json` with parent directory 0700 and file permissions 0600. **0 projects were selected by default**. The private inventory was **not committed to Git**.
2. The public `PeterxVarga/tredven-upstream` repository (GitHub repo ID `1467524521`) was explicitly selected. A read-only review found Rust/Cargo source manifests and GitHub CI paths; it located upgrade-related PR candidates, not arbitrary claims about all dependencies.
3. Explicit PR #9 yielded real GitHub base `a242e5dbe348b01adeb8948e003b019a586bdf0d`, head `44d6eef16de40e33474e578c0ffcd7a2e1b4c698` and 10 changed paths. The existing Rust preflight classified them as `DEPLOY_OR_DEPENDENCY: 1`, `OTHER: 9`, but correctly returned `UNKNOWN`: no signed source or integration/rollback test. No merge/deploy/upgrade permissions.
4. Launched `github-workspace dashboard` locally, bound to **127.0.0.1 on an ephemeral port**, and executed an actual HTTP E2E: GET dashboard, verify source state and exact nonce CSP, unauthorized CSRF POST returns 403, forged Host returns 403, authorized POST deselects and reselects only this public project, shared CLI state reflects each mutation, then authorized POST `/review` with PR #9 runs the real GitHub API + native Rust impact classifier. Correctly still `UNKNOWN`. The local server was stopped after the test, no external access/deployment.
5. Tried to attach genuine previously observed R29 PostgreSQL/Celery test receipts to the unrelated public PR #9 using a **copy** of the private synthetic Git fixture with locally configured matching `origin`; the optional R29 core checked the fixture, but the R30 wrapper returned `LOCAL_SYSTEM_EVIDENCE_COMMITS_NOT_EXACT_GITHUB_PR`, and the public PR remained `UNKNOWN` with no attached gate or authorization.
6. Unit tests cover private atomic persistence, no implicit monitoring/authorization, account/repository identity, cross-account and content spoofing constraints, GitHub pagination across two mocked pages with 101 repositories, purging revoked resources, HTML injection escaping, symlink and directory permission rejection, and fake R29 authorization rejection.

**Evidence level:** authenticated real GitHub metadata + real native Rust source-impact code + local loopback HTTP E2E. **NOT** real GitHub App OAuth, not hosted dashboard, not paid customer validation, not a background daemon, not a real compatibility E2E for GitHub PR #9, not CI-signed production proof.

## Reproduce (reviewed local development branch only)

Requires a Linux development machine, working `gh auth login` already managed by the user, and access to the repository GitHub APIs. No repository mutation or deployment is performed.

```bash
# From the source repo's root, after building the current branch:
cargo build --locked

# State root MUST be a private real directory, chmod 0700
install -d -m 700 output/my-private-workspace
export WORKSPACE_STATE="$PWD/output/my-private-workspace/state.json"
export BIN="$PWD/target/debug/tredven-upstream"

# One-time inventory, no monitoring enabled
"$BIN" github-workspace discover --state "$WORKSPACE_STATE"
"$BIN" github-workspace list --state "$WORKSPACE_STATE"

# Choose a GitHub repository ID shown in the inventory
"$BIN" github-workspace select --state "$WORKSPACE_STATE" --id REPO_ID --on
"$BIN" github-workspace review --state "$WORKSPACE_STATE" --id REPO_ID --pr PR_NUMBER

# Local UI. Press Ctrl-C to stop; never publicly expose this loopback port.
"$BIN" github-workspace dashboard --state "$WORKSPACE_STATE"

# Optional: only if there is a real, exact source-bound R29 Compose test config:
"$BIN" github-workspace qualify --state "$WORKSPACE_STATE" \
  --id REPO_ID --pr PR_NUMBER --config /private/local/compose-qualification.json

# Deselect and clear report; continuous monitoring is not yet implemented
"$BIN" github-workspace select --state "$WORKSPACE_STATE" --id REPO_ID --off
```

The local dashboard does **not** install a GitHub App, create organizations, emit telemetry, send source to an external Tredven service, or generate provider write credentials. The GitHub CLI's existing authenticated REST calls are the only remote operations. No token is copied to the workspace file.

## Follow-up: highest-value remaining gaps

1. **Real GitHub App user onboarding** with limited repository installation scopes and a service-side permission boundary; preserve provider/account/repository ID identity and bind the hosted session. Permission changes and revocation must fail closed.
2. **Actual on-demand project-specific upgrade evidence**, not mere filename/PR heuristics. Reuse Renovate's candidate PR, the exact project CI and existing R29 Rust gate; only launch untrusted runtime containers in isolated approved runners with declared expenses.
3. **Selected-project scheduled or webhook monitoring**, initially read-only, rate-limited and revision-pinned; do not treat selection as an active subscription until background execution and revocation are proven.
4. One shared API usable from dashboard, CLI and future read-only MCP. No three independent engines or local token storage.

**Full project status — PARTIAL.** Functional readiness `UNKNOWN` (Δ `UNKNOWN`), integrated E2E `UNKNOWN` (Δ `UNKNOWN`), production readiness `UNKNOWN` (Δ `UNKNOWN`); no reproducible denominator across all project requirements. The **R30 local first-use vertical is COMPLETED**; the commercial end-to-end hosted GitHub App and production upgrade path remain unverified.
