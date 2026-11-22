# Porting the existing upgrade gate to Rust

This is a **new public core**, not a publication of the private internal integration and approval infrastructure.

## Read-only legacy baseline (private, not included)

Internal reference at the time the new public core was started:

- The original implementation is in a separate private workspace; **do not copy source pins, private receipts, tenant bindings or operational launchers here**.
- Python gate: 408 lines of source/adapter compatibility and patch safety evidence integration.
- Python tests: 21/21 targeted offline regressions **observed on the internal Fedora checkout** before the new port.
- Existing connected-provider contracts and historical patch/database evidence remain private and are not part of the new public CLI.

## Rust Anything reuse decision

[erkamyaman/rust-anything](https://github.com/erkamyaman/rust-anything) (MIT) is a relevant **optional migration verification tool**, not a dependency of this CLI.

- Its useful mechanism: **record original behavior, port one bounded unit, compare cases, gate the replacement**.
- It does **not** translate or implement Rust by itself. AI or a developer must write that code.
- **Never run `rust-anything record`, `app record`, `diff` or `app replay` on an owner-private runtime without an isolated source copy and an entirely synthetic, credential-free environment.** Recording can replay file/network/DB effects many times.
- No `rust-anything` binary or MCP server is required to build or test this public repository. We are not claiming its `gate` has passed.

## Baseline scope and honest parity level

First migrated concepts: deterministic source identity comparison, changed-path categories, evidence-state precedence, JSON/Markdown reporting and always-denied authority. This is not a byte-for-byte port of the 408-line Python tool: live Git/GitHub fetching, secure source pin checks, legacy receipt verification and runtime adapters have **not** been ported.

The current unit/CLI suite covers caller-supplied, synthetic fixtures only. On an owner-controlled environment, an additional **private** differential test may compare the generic path-classifier cases to the legacy Python `kind()` function; only sanitized generic input/output belongs in public fixtures.

## Staged E2E milestones

1. **COMPLETE (local):** compile a stand-alone Rust binary, deterministic synthetic JSON/Markdown output, fail-closed status, error codes, tests and local formatting/lint checks.
2. **NEXT:** local **read-only official Git source release adapter** with exact commit/tag verification, bounded HTTP responses, no redirects, no provider authentication and explicit truncated compare coverage; independently compare behavior against private existing gate fixtures.
3. Add a neutral extension protocol for versioned, declarative source-verified rules and optional application-specific smoke-test evidence. No arbitrary downloaded executable rules.
4. Demonstrate two real public upgrade pairs with a meaningful gap not already handled by Renovate or an application's native migration report.
5. Only separately and explicitly authorized: public v0.x release, opt-in X communication, and actual budget-holder tests for managed verified intelligence infrastructure.

## Stop conditions

Missing verified source, partial diff, unavailable local runtime, untested rollback, corrupt provenance or a newly moved upstream target is **never** interpreted as safe production readiness.

Do not create a second production authority or import Tredven customer data into public test fixtures. Never treat Rust build success, GitHub stars or social reach as paid-user validation.
