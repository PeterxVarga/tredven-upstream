# R6 — Native scanner evidence and one-command upgrade review (Rust core)

**Date:** 2026-11-22
**Development branch:** `feat/native-scanner-evidence-r6-20261122`
**Scope:** independent **public MIT Rust CLI**; private Tredven, Warmbly, Netcup, owner-stage work intentionally deferred.
**Status:** R6 standalone-source and synthetic CLI behavior qualified locally; **no real scanner execution or Tredven production/self-use test**.

## Strategic goal

Make the existing read-only Rust `tredven-upstream` genuinely useful without forcing operators to manually turn machine-readable vulnerability scanner results into unverified `passed`/`failed` statements. Keep Renovate, Trivy and OSV-Scanner as incumbent producers; **read and interpret their existing JSON output**, associate it with a pinned local Git candidate, and emit a conservative single decision.

### ROI challenger before implementation

1. Keep writing one-off OpenSEO or Warmbly SQL/config rules — **not selected**. The R4 counterfactual showed a 43-line existing-stack script can duplicate a narrow static migration check. It doesn't unblock general OSS usability.
2. Build a hosted dashboard, registry tracker, vulnerability database or rewrite Trivy — **not selected**. Duplicate mature ecosystem code, operational expense, user friction and security responsibilities without customer benefit evidence.
3. **Selected: native Trivy + OSV-Scanner JSON consumer**, reused in both multi-target plans and a one-command local Git + scanner CLI. Addresses R5's demonstrated manual normalization gap with minimal new dependencies (none).
4. Public release automation/managed service — defer until the independent Rust user flow has trustworthy usage and external validation.

## Feature surface

### A. Inspect a scanner report directly

```bash
cargo run --locked -- inspect-scan \
  --input fixtures/scanner/trivy-critical.json \
  --scanner trivy-json-v2 \
  --subject 'example/app@sha256:synthetic-candidate' \
  --format markdown

cargo run --locked -- inspect-scan \
  --input fixtures/scanner/osv-vulnerable.json \
  --scanner osv-scanner-json-v2 \
  --subject Cargo.lock
```

**Exit codes:** 2 BLOCKED (confirmed high-risk or mismatched subject), 3 UNKNOWN (no qualifying package/source coverage or malformed/unsupported output), 0 REVIEW (no blocking findings *in the parsed scope*, still not an approval), 1 invalid CLI input. The `--subject` value must exactly match Trivy `ArtifactName` or every OSV-Scanner `results[].source.path`.

### B. Inspect a **local** source release and scanner evidence in one Rust command

```bash
# Prepare your own scan JSON with your normal security tool OUTSIDE this program.
# Tag and commit values come from the EXISTING source repo. Do not read
# "scan-commit" as a cryptographically signed scanner attestation:
git -C /ABS/PATH/TO/LOCAL/SOURCE rev-parse 'refs/tags/v1.1.0^{commit}'

cargo run --locked -- inspect-upgrade \
  --repo /ABS/PATH/TO/LOCAL/SOURCE \
  --project example-app \
  --from v1.0.0 --to v1.1.0 \
  --scanner trivy-json-v2 \
  --scan-report /ABS/PATH/TO/EXISTING/trivy-report.json \
  --subject 'your-exact-trivy-ArtifactName' \
  --scan-commit '40-HEX-CHARACTER-CANDIDATE-COMMIT' \
  --format markdown
```

No hand-written JSON manifest needed. The Rust CLI validates the **local** Git tag identities, hashes the supplied report file, binds the **caller-asserted** candidate commit to the inspected tag, parses the report and generates an existing R5-style source/evidence/decision report. It does NOT check that the third-party scanner actually scanned the exact tag, repository or image: **that identity remains a caller assertion**. The source Git objects do not authenticate the remote publisher.

### C. Multi-target watch plan with native scanner input

Existing `inspect-plan --manifest FILE` stays backward-compatible. A native scan evidence object adds one optional `scan` field:

```json
{
  "id": "security-scan",
  "source_tool": "trivy",
  "status": "unknown",
  "candidate_commit": "REPLACE_WITH_EXACT_40_HEX_GIT_COMMIT",
  "artifact": {
    "path": "/ABS/PATH/TO/EXISTING/trivy.json",
    "sha256": "REPLACE_WITH_SHA256_OF_EXACT_REPORT_BYTES"
  },
  "scan": {
    "format": "trivy-json-v2",
    "expected_subject": "REPLACE_WITH_EXACT_TRIVY_ArtifactName"
  }
}
```

For OSV-Scanner use `source_tool: "osv-scanner"`, `format: "osv-scanner-json-v2"` and the exact `results[].source.path`. The `status` field **must** be `"unknown"` for the native scanner; the Rust parser determines the actual evidence outcome. A manually asserted `"passed"` with `scan` is explicitly rejected. All other legacy R5 caller-asserted evidence entries are unchanged.

[Disabled manifest example](../examples/watch-plan-native-scanner.example.json) intentionally contains invalid placeholder paths, hashes and tag names and has `enabled: false`: safe to inspect, **not** an executable production plan.

## Exact parsing contract, coverage and limits

Official public schema references (format research, not code reuse):
- [Trivy: JSON report format](https://trivy.dev/docs/latest/guide/configuration/reporting/#json) describes `SchemaVersion: 2`, `ArtifactName`, `Results`, `Vulnerabilities` / `Severity` and optional misconfiguration/secret findings.
- [OSV-Scanner V2: JSON output](https://google.github.io/osv-scanner/output/#json) describes `results[].source.path`, `packages[].package`, `vulnerabilities` and aliases/groups.
- [OSV-Scanner return code caveat](https://google.github.io/osv-scanner/output/#return-codes): no package discovery is different from a successful scan of actual packages.

**Trivy v2:** Counts vulnerabilities, misconfigurations and secret occurrences **separately**. Parses only `SchemaVersion=2`, exact `ArtifactName`, non-empty `Results`, and finding arrays. `HIGH`/`CRITICAL` vulnerability or misconfiguration, or any secret finding → **BLOCKED**. Unknown/missing severity, malformed findings or unverifiable vulnerability scanning coverage → **UNKNOWN** if no confirmed block. Valid scoped report with no blocking findings → **REVIEW**, not an all-clear. Medium/low findings are counted; they are NOT safety permission.

**OSV Scanner V2:** Exact `source.path` requirement for every parsed result. Any vulnerability occurrence → **BLOCKED** even if another entry is incomplete. A matching source with nonempty parsed packages and no reported vulnerabilities → **REVIEW**. Empty results, no packages or malformed entries without confirmed findings → **UNKNOWN**. We do **not** pretend to infer uniform CVSS severities or deduplicate advisory aliases: counts are reported as **occurrences**.

**Trust and coverage:** Scanner JSON content is untrusted. An SHA-256 digest of the same bytes checked and parsed establishes only **local file integrity**; a user who creates both the JSON and hash could forge both. Local Git commit pairing and tool labels are also not independent attestations. This program does not check scanner binary provenance, actual scanner run, run timestamp, scan completeness, real source/image matching, remote tag authenticity, production runtime, rollback or owner permissions. Accordingly `source_commit_attested_by_scanner=false`, `scanner_execution_attested=false`, `complete_scan_coverage_attested=false`, `production_ready=false`, and no action authority is issued.

**Read-only and limits:** No shell scanner execution, network fetch, privileged agent, credentials, Docker, DB, Git checkout, write, send, merge, deploy or release. Scanner JSON is read from a normal non-symlink file up to 8 MiB; watch manifests remain 512 KiB, ordinary R5 opaque artifacts remain 1 MiB. Scanner artifacts may be 8 MiB. Parsing uses **exactly the bytes hashed by the R5 plan**, avoiding hash-then-reopen TOCTOU. No raw secret finding or arbitrary third-party description is emitted in the report: only aggregate counts and bounded fixed reasons.

## Verification levels and acceptance

**Executed on Fedora local Rust toolchain, 2026-11-22:**

- Historical R5 baseline: 50/50 tests passing on its exact preceding feature branch.
- R6 additions: **11** scanner unit tests, **12** Git+watch-plan scanner integration tests, **7** standalone scanner CLI tests, **5** one-command source+scanner tests = **35** additional tests.
- Total **85/85 PASS**: 35 unit + 6 legacy CLI + 10 Git integration + 27 watch-plan + 7 standalone scanner CLI. `cargo fmt --check` and strict `cargo clippy --locked --all-targets -- -D warnings` PASS.
- Optimized local **`cargo build --locked --release` PASS** on Fedora; native binary about **1.0 MiB** (not uploaded, signed, tagged or independently verified as a distribution). The release binary was executed on **five** local synthetic scanner outputs: critical/clean/empty Trivy and vulnerable/empty OSV, all with expected 2/0/3 exit statuses and no action authority. Disabled watch-plan smoke test also exited 3 with zero watched targets.
- Seven independent **purely synthetic** Trivy/OSV-shaped fixtures. Tests demonstrate critical → BLOCKED, secret finding → BLOCKED, no finding on a structurally scanned subject → REVIEW, empty/unknown coverage → UNKNOWN, fake scanner PASS assertion → validation error, wrong candidate commit → BLOCKED, SHA mismatch → BLOCKED, source+scanner one-shot CLI behavior and no action authority.
- The public scanner report field shapes were researched from **actual up-to-date official documentation**, but the scanner binaries were **not executed** and no real scan artifact was ingested. **Original Tredven/Warmbly source, native stage, PostgreSQL, production, customer data and SaaS billing were intentionally not touched** at the user's request.

## Current gaps, next ROI without internal testing yet

- Scanner integrity/source matching is not independent provenance. Later integrate native scanner execution receipts or signed CI attestations; not fake the evidence.
- JSON adapter does not yet normalize arbitrary scanner formats, Trivy K8s, SARIF, software inventories, advisory suppression policies or complete runtime health.
- Need better onboarding and packaging (prebuilt Linux release, verified supported toolchain), operator ergonomics and realistic public fixture coverage before broad distribution.
- **Keep future Tredven internal-use E2E as a separate, authorized phase**. Do not invoke owner-stage, production or outbound checks during Rust-core product development.

**Final state:** R6 Rust-native scanner vertical **COMPLETE (isolated source/synthetic test level)**; whole OSS product **PARTIAL**; external user value and buyer willingness to pay **NOT PROVEN**. Functional readiness **UNKNOWN (Δ UNKNOWN; no reproducible full feature denominator)**; integrated E2E **UNKNOWN (Δ UNKNOWN; no real external tool-to-source attestation and no deployment)**; production readiness **UNKNOWN (Δ UNKNOWN; no release approval or live user proof)**.
