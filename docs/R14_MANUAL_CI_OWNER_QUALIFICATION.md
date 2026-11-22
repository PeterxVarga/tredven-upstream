# R14 — Owner-gated manual public CI qualification

Date: 2026-11-22. Base: `286814b74b8439eb883fcd276c07cf94bbbc3745` (R11).
Branch: `feat/r14-manual-ci-owner-qualification-20261122`, **local only**.
Scope: one public synthetic/reference GitHub Actions scanner workflow; no private customer data, no push, merge, dispatch, signed public record publication or deployment.

## Canonical state and gate

- The GitHub repository `PeterxVarga/tredven-upstream` is public (ID `1467524521`).
- GitHub Actions was checked **enabled=true**, `allowed_actions=all`, and default workflow permissions `read`.
- GitHub's current Actions workflow list reports **zero registered workflows**; `main` at `42a749d9845dcfb4eb553760021e42c035b981c4` does not contain the R11 workflow.
- GitHub requires a `workflow_dispatch` definition on the **default branch** for first manual dispatch. Thus the hosted signed scan is **BLOCKED pending owner-approved publication to main**.
- This branch intentionally descends from R11, not the later independent R12 license branch or R13 research branch. Those remain separate local changes; no implicit merge or loss of their work is authorized.

## Concrete R14 changes

1. The manually dispatched job is now allowed **only** when repository name and immutable ID match, `github.ref == 'refs/heads/main'`, and `github.event_name == 'workflow_dispatch'`. It remains GitHub-hosted `ubuntu-24.04`, with only `contents: read`, `id-token: write`, `attestations: write` and no push, PR, schedule, cron or self-hosted runner.
2. The receipt generator independently rejects non-`main` GitHub source refs; the existing exact source/report hashes, pinned OSV 2.7.1 checksum, observed status 0/1, public sample scope and refusal of production authorization remain unchanged.
3. The pinned official `actions/attest-build-provenance` action now exports its `bundle-path` into the same **public-only** artifact as the original receipt/reports. The bundle is size checked and copied without running a new signer. An independent verifier still needs a **separately trusted** Sigstore root, exact source signer policy, genuine GitHub Actions identity and local source/report matching. The bundle itself is **untrusted input**, not proof just because it was attached.

The three original action SHAs were checked against the actual upstream GitHub commits:
- `actions/checkout@11d5960a326750d5838078e36cf38b85af677262`
- `actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8`
- `actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02`

None are replaced by a loose tag. The action's official `bundle-path` output is documented upstream. No new action, service, direct private key or dependency was added.

## Proportionate evidence

- PyYAML BaseLoader parsed the workflow and asserted the only event is `workflow_dispatch`, strict main/repo/event guards, 8 steps, the official bundle output, explicit permissions and no automatic triggers.
- Every `run` step passed `bash -n`.
- Public-fixture receipt generator: **10/10 Python tests PASS**, including rejection of a non-main branch, forged source, changed report/lockfile, missing run identity and unobserved scanner exit.
- `cargo fmt --check`: PASS; `cargo clippy --offline --locked --all-targets -- -D warnings`: PASS.
- `cargo test --offline --locked --all-targets`: **156/156 Rust regression tests PASS** (local, no hosted CI).
- Existing R11 genuine public OSV scan: **already completed locally**, not repeated. Its raw reports and scanner results are not new hosted proof.
- **NOT PROVEN:** GitHub-hosted workflow run, actual persisted attestation, download/export of the signer bundle, independent signed scanner CI verification, safety of any user upgrade, production readiness.

## Next bounded owner gates

1. Review and explicitly authorize publishing the reviewed R14 Git branch as a pull request, then separately review/merge the resulting canonical workflow into `main`. Merely publishing a branch does **not** enable the workflow's first manual run.
2. **After** the exact canonical commit is reviewed and confirmed, separately authorize **one** `workflow_dispatch` on `main`. Expected run creates only public fixture lockfiles/reports and posts a GitHub attestation and short-lived public artifact; no service deployment or paid query.
3. Download signed evidence; independently obtain a trusted Sigstore root (never trust a root bundled by the signer), verify `ci-run.receipt.json` with patched `gh` and compare signer commit, workflow path/run ID, original source Git SHAs and both report/lockfile hashes through the existing R11 Rust verifier. Scanner exit 1 means findings, not success clearance. Remain `REVIEW` or `BLOCKED`; no release authority.

No push, PR, merge or dispatch was executed here. Branch is suitable for owner review, not a claim of hosted end-to-end acceptance.

## ROI and full-project status

Three options considered: (A) build extra Witness/Chainloop integration, (B) add CI infrastructure or synthetic replay, (C) fix exact GitHub-native default-branch gate and offline evidence handoff. **Selected C**: smallest intervention on the critical path, based on R13's falsified Witness command-exit-1 approach and already integrated R11 verification.

Functional completeness: **UNKNOWN** (no reproducible roadmap denominator). Integrated E2E completeness: **UNKNOWN** (hosted signed scanner vertical not executed). Production readiness: **UNKNOWN** (no customer/runtime qualification, signed release, permission or demand validation). Deltas: **UNKNOWN**, no comparable historical whole-project measurement. The narrower local R14 checks are reproducible PASS; they do not imply project-level percentages.

References:
- https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow
- https://github.com/actions/attest-build-provenance/blob/main/action.yml
- https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline
- https://cli.github.com/manual/gh_attestation_verify
