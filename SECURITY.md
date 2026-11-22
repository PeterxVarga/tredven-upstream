# Security

**Pre-alpha / source-only prototype.** Tredven Upstream does not access a live upstream, cluster, Docker socket, production database or credentials. It does not grant operational authority.

## Data handling

- Use only sanitized manifests. `inspect` accepts a local file or stdin; `inspect-git` reads only a local Git repository and its two named tag objects. Neither mode uploads data or contacts providers.
- `inspect-git` requires an existing Git checkout and installed `git`; it does not clone, fetch, checkout, modify working files, invoke hooks or external diff programs, or execute code from Git objects. It ignores uncommitted files.
- `inspect-contract` resolves *one* hard-pinned migration Git blob and a baseline Drizzle schema source blob. It does not execute SQL or connect to any database. Optional caller-provided JSON snapshots are unverified; omitted or incompatible parent tables in a partial snapshot must not be treated as independently confirmed live database absence. A BLOCKED result is a safety stop for the inspected evidence only.
- **Local Git objects do not attest the upstream publisher.** Even an exact local Git commit SHA can come from an untrusted or forged local repository. The report explicitly marks `LOCAL_GIT_OBJECTS_REMOTE_UNATTESTED`.
- Reports may contain source filenames. Treat output from private repositories as sensitive, and do not post internal reports on GitHub or X.
- **Do not submit secrets, internal endpoints or customer records** in GitHub issues, bug reports, examples or pull requests.
- The caller supplies all evidence and may lie; `source_verified` does not represent cryptographic verification.
- `BLOCKED` means stop and inspect. `REVIEW` and `UNKNOWN` also do not mean safe to deploy.
- Exit code 0 means the CLI ran successfully, **not that an upgrade is authorized**.

## Watch-plan trust model

- `inspect-plan` accepts bounded JSON, **opts out by default**, and reads only local Git objects and user-selected external evidence files. It never runs the named CI/scanner or performs image checks, network calls, backups or deploys.
- Each declared PASS requires an SHA-256-matching local artifact and a candidate commit matching the inspected local Git tag. This is **not** independent evidence that the scanner ran, the result is fresh, the remote publisher is authentic or the release is safe. A source-specific artifact can be forged together with its digest.
- A failed check or tampered artifact blocks the selected target. Missing checks or absent proof remain UNKNOWN. Even all declared gates satisfied produces REVIEW, not authorization.
- Source paths and input artifact paths are read-only, and the tool does not print raw artifact contents. However, users should keep internal Git receipts and reports private; malformed or adversarial local source trees are not a substitute for an OS sandbox.
- Do not wire this prototype to automatic production deployment or a privileged long-lived GitHub Actions runner.

## Native scanner evidence trust boundary (R6)

- `inspect-scan` consumes bounded local Trivy JSON schema v2 or OSV-Scanner v2 JSON. **The CLI never runs either scanner**, and parsing a JSON file is not independent proof of tool execution, coverage, currentness, vulnerability database quality, source commit or image identity. Scanner versions and policies can change; unknown/malformed/unsupported reports fail to `UNKNOWN`, not READY.
- `inspect-upgrade` combines local Git tag inspection with the scanner bytes. The `--scan-commit` field is a **caller assertion**, compared to the candidate tag; a mismatch is BLOCKED. A matching caller assertion cannot attest that a scanner actually analyzed those bytes. Do not wire its exit code 0 to privileged deploy or merge automation.
- Inside a watch plan, native scanner evidence must use `status: "unknown"`, not a fabricated `passed`. Results are parsed from the **same exact bytes** that were hashed against the supplied SHA-256, avoiding a hash/parse second-read race. The operator controls the digest and file; **no cryptographic tool or scan signature** is verified.
- Trivy findings with HIGH/CRITICAL severity or any detected secret are blocking; unrecognized severity, empty results and absent scan coverage are UNKNOWN. OSV advisory occurrences are blocked (no speculative severity conversion); empty/no-package reports are UNKNOWN. Those policies are **conservative heuristics**, not a comprehensive vulnerability triage decision.
- Scanner files are max 8 MiB; regular files only, no final symlink, no raw secret content printed. Reports include aggregate finding counts and source paths from local Git. Treat private reports as sensitive. Input is untrusted JSON; no arbitrary commands, build scripts or code inside files are executed.

## R7 baseline/candidate delta — a comparison, not proof of a safe upgrade

- `inspect-delta` reads **two existing**, bounded, non-symlink scanner JSON report files; `inspect-upgrade-delta` additionally reads only named local Git tags and compares **caller-asserted** baseline/candidate SHA-1 commit declarations against those local Git objects. These declarations do not cryptographically attest that the scanner ran on the particular commit, that its database was fresh, or that the remote Git publisher is genuine.
- Vulnerability identity uses exact category, source/scanner target, package and advisory ID; Trivy different `Target`, `Class`, `Type` or scanner-array coverage are **not** considered comparable. OSV source path/type changes are likewise not comparable. Missing scans, malformed IDs and changed source coverage produce **UNKNOWN** and null delta counts (rather than invented zero improvement).
- The delta and the **absolute** candidate verdict are separate. A persisting critical/high vulnerability, secret or OSV advisory still makes the final result **BLOCKED**, even when the delta contains no new findings. A new medium/low finding remains visible and REVIEW-only, never an approval. Severe escalation is also a delta blocker.
- Scanner JSON files can contain real secrets, credentials and internal path names. The program never sends scanner files over the network, runs the scanner or prints finding descriptions/secret match bytes, and limits examples to 20 sanitized IDs. It can expose package/advisory names and local Git paths: **do not publicly share private reports**.
- A scanner's own suppressed or incomplete findings, stale vulnerability database, changed scan flags, hidden aliases and lack of independent signed attestation are **not** solved by the diff. Use the original vendor tools for actual vulnerability analysis and production policy.

## R8 local release receipt: integrity is not authenticity

- `scripts/release_candidate.py build` requires a clean Git commit, pinned local Rust toolchain, offline Cargo cache, fmt/Clippy/tests/optimized build and `cargo package`. Outputs are only created inside locally ignored `output/`; never automatically uploaded, published or deployed.
- `verify` checks a local checksum list, fixed SHA256 manifests, normalized archive metadata and bounded regular-file scope. **An attacker who can alter all files can also recompute the checksums**. Neither the checksum list, user-supplied source commit nor self-authored manifest is an independently signed attestation or publisher proof.
- Every receipt explicitly states no signature, scanner execution attestation, production readiness, publication or deployment authorization. If signed evidence is needed, use upstream GitHub/Sigstore verification **with issuer/repository identity constraints**, not this local integrity verifier as a trust root.
- Candidate files are not a promise of cross-host reproducible binaries or a release ready for arbitrary Linux distributions. No CI token, GitHub release, crates.io publication or secret is required or used.

## Report vulnerabilities

Use GitHub's private vulnerability reporting if enabled, or contact the project maintainers through the repository's security reporting channel. Do not publicly post exploit payloads with real user data.

## Non-goals

No background service, telemetry, credentials, arbitrary remote scripts, production mutations or guaranteed security verdicts. This project is not a security scanner or a production upgrade orchestrator.
