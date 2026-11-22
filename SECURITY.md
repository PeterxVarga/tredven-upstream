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

## Report vulnerabilities

Use GitHub's private vulnerability reporting if enabled, or contact the project maintainers through the repository's security reporting channel. Do not publicly post exploit payloads with real user data.

## Non-goals

No background service, telemetry, credentials, arbitrary remote scripts, production mutations or guaranteed security verdicts. This project is not a security scanner or a production upgrade orchestrator.
