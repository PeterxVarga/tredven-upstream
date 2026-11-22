# R7 — Source-bound scanner upgrade delta (Rust core)

Date: 2026-11-22. Development branch: `feat/scanner-upgrade-delta-r7-20261122`, parent R6 commit `0a1e7171dbbeb27252dc080016145e3fc8ced696`.
Scope: independent public MIT Rust CLI. **Private Tredven system testing and production are intentionally deferred.** No scans, service startups, network requests, sends, merges, deployments, public release tags or customer data.

## User-facing outcome

Two existing, local Trivy JSON v2 or OSV-Scanner v2 reports can be compared to separate **new, resolved, persistent and escalated** findings. Results are also available in a one-command local-Git-pinned source upgrade review.

```bash
cargo run --locked -- inspect-delta \
  --baseline fixtures/scanner/trivy-clean.json \
  --candidate fixtures/scanner/trivy-critical.json \
  --scanner trivy-json-v2 \
  --subject 'example/app@sha256:synthetic-candidate' --format markdown

# For an existing local source clone and previously-produced scan reports:
cargo run --locked -- inspect-upgrade-delta \
  --repo /ABS/PATH/TO/LOCAL/GIT/SOURCE \
  --project example --from v1.0.0 --to v1.1.0 \
  --baseline /ABS/PATH/TO/BASELINE/SCANNER.json \
  --candidate /ABS/PATH/TO/CANDIDATE/SCANNER.json \
  --scanner osv-scanner-json-v2 --subject Cargo.lock \
  --baseline-commit REPLACE_WITH_BASELINE_GIT_SHA \
  --candidate-commit REPLACE_WITH_CANDIDATE_GIT_SHA \
  --format markdown
```

The example is **synthetic**; the R7 tool does not execute either scanner. A matching user-supplied commit value is **not** proof of scanner execution against that commit. It only means the declared value matches an existing locally resolved Git tag. The report separately marks remote-publisher identity, scanner authorship, scan completion, signed verification, production readiness and action authorization as unverified/false.

## Decision contract (no false green)

| Case | Delta | Final |
| --- | --- | --- |
| New HIGH/CRITICAL or a new OSV advisory | BLOCKED, new count visible | BLOCKED |
| Persisting CRITICAL on both versions | REVIEW, new=0 | **BLOCKED** (existing absolute candidate risk) |
| Existing finding escalated LOW to HIGH | BLOCKED, escalation count | BLOCKED |
| A HIGH finding disappears in comparable scope | REVIEW, resolved count | REVIEW **not READY** |
| New MEDIUM/LOW | REVIEW, newly introduced count | REVIEW **not READY** |
| Baseline missing or malformed scanner data | UNKNOWN, new=null | UNKNOWN or BLOCKED on candidate absolute severity |
| Different scan targets, class/type or scanner array coverage | UNKNOWN, new=null | UNKNOWN or BLOCKED on candidate absolute severity |
| Wrong baseline/candidate source-commit declaration | N/A | BLOCKED |

Null delta count means missing comparative evidence, **not** zero. A successful exit 0 is always only a review suggestion. Exit 2 = blocked; 3 = unknown; 1 = malformed CLI invocation.

## OSS ROI challenger

Options evaluated: (A) build another standalone scanner / advisory DB / SaaS dashboard: rejected as duplicative; (B) add only release packaging/CI now: deferred since it does not change upgrade reasoning; (C) implement a universal cryptographic attestation verifier from scratch: rejected, use trusted OSS if signed fixtures become available; (D) **selected narrow cross-format source-bound delta**, preserving absolute safety.

**Important contrary evidence:** Google’s [OSV-Scanner GitHub Action](https://github.com/google/osv-scanner-action/blob/main/.github/workflows/osv-scanner-reusable-pr.yml) already compares old and new scanner results via its reporter and fails when scans produce no report. [osv-ui](https://github.com/toan203/osv-ui) already supports `--baseline`. [Anchore Yardstick](https://github.com/anchore/yardstick) compares results from different scanners. Therefore **CVE delta alone is not a commercial differentiator**; R7 is only a narrow, read-only multi-scanner/Git workflow convenience, and should not spawn another framework without measured use.

Official JSON reference docs: [Trivy report format](https://trivy.dev/docs/latest/guide/configuration/reporting/), [OSV-Scanner output](https://google.github.io/osv-scanner/output/). The independent Rust implementation copies **no upstream code**, libraries or incompatible licenses.

## Comparison limitations

- Trivy: exact `SchemaVersion=2` and `ArtifactName`, structural `Results` presence and exact **target + class + type + scanner array presence** on each side. Multiple scanner rows for one target are supported. Missing vulnerability scan results cannot be inferred as a zero-finding scan. A new secret can still make the absolute candidate BLOCKED when baseline scope is UNKNOWN.
- OSV-Scanner: exact `source.path`, `source.type`, nonempty recognized packages, and exact advisory/package/ecosystem keys. The same advisory after a dependency version change remains persistent, not falsely resolved. Counts represent occurrences, not deduplicated CVEs or complete package inventories.
- Finding IDs and package strings are bounded and checked for control characters; secret match contents and long advisory descriptions are not printed. Output includes no more than 20 new-finding examples, plus complete bounded counts.
- An SHA-256 of locally supplied input bytes verifies the reporting bytes only. Two different vulnerability DB versions, scanner flags, suppression policies, OSV alias groups, signed report origin and actual running-service behavior remain **UNKNOWN**.
- Two local files are bounded (8 MiB each), must be normal non-symlink files. The Git command reads named local tags without a checkout or remote fetch. It never executes source code.

## Qualification, readiness and next ROI

R6 baseline: **85/85** Rust tests on owner Fedora. R7 tests cover persistent severe blockers, new/resolved findings, severity escalation, same-target different scanner scopes, missing/invalid scope, bounded samples, synthetic secret content redaction, original scanner outcome and actual CLI subprocess execution with disposable local Git tag pairs.

**Observed local acceptance on Fedora Rust 1.100.0:** 108/108 Rust tests PASS (48 library, 6 legacy CLI, 10 existing Git CLI, 10 new delta CLI, 27 watch-plan CLI, 7 scanner CLI), `cargo fmt --check` PASS, strict `cargo clippy --locked --all-targets -- -D warnings` PASS, optimized `cargo build --locked --release` PASS. The optimized binary was smoke-tested with three synthetic Trivy evidence pairs: introduced CRITICAL → exit 2/BLOCKED, persistent CRITICAL → delta REVIEW but overall exit 2/BLOCKED, unknown baseline → exit 3/UNKNOWN and `new_occurrences: null`. `cargo package --locked --allow-dirty --offline` verified a 43-file source crate locally, no publish/upload. All Rust tests and optimized binary smoke runs in this scope are **local or synthetic**; neither Trivy nor OSV was actually run on Tredven’s real application. The feature is not evidence of production E2E. Full functional readiness **UNKNOWN (Δ UNKNOWN; no total feature denominator)**, integrated E2E **UNKNOWN (Δ UNKNOWN; no independently attested scanner run/source binding)**, production **UNKNOWN (Δ UNKNOWN; no deploy/release)**; external paid value **NOT PROVEN**.

**Next better ROI:** avoid extending the bespoke delta logic; integrate existing secure GitHub/Sigstore verification *if and only if* real signed bundles are available, and improve reproducible local packaging. Own-system E2E remains separate, as requested.
