# Security

**Pre-alpha local-first CLI with unsigned release candidates.** Tredven Upstream does not access a live cluster, Docker socket, production database or application credentials. Some explicitly selected commands invoke external scanners or query public APIs; see the opt-in boundaries below. It does not grant operational authority.

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

- `inspect-scan` consumes bounded local Trivy JSON schema v2 or OSV-Scanner v2 JSON. **This parser command does not execute either scanner.** The opt-in `review-local` and `review-upgrade` executable scan paths are different, as documented under R10 and R18 below. Parsing imported JSON is not independent proof of tool execution, coverage, currentness, vulnerability database quality, source commit or image identity. Scanner versions and policies can change; unknown/malformed/unsupported reports fail to `UNKNOWN`, not READY.
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

## R9 GitHub/Sigstore verifier trust boundaries

- `verify-attestation` and `inspect-attested-scan` call the **installed official `gh` binary** as an external verifier and inspect its *cryptographically verified* JSON certificate results. Rust does **not** implement any new DSSE/X.509, Sigstore, Rekor or TUF cryptographic verifier. The executable found as `gh` in the operator PATH is part of the trusted computing base.
- Identity is **strictly pinned** by operator-supplied expected GitHub `owner/repo`, immutable repository ID, exact signer workflow path, source Git ref and 40-hex commit SHA. The program also requires the signed statement's subject filename and SHA-256 to match the actual local file, a verified timestamp and a GitHub-hosted runner. Name-only or owner-only validation is insufficient for trusted unattended updates.
- **Offline is the default.** A local signed bundle and custom trusted root must both exist; missing trust data BLOCKS rather than performing a network fallback. An offline custom root is **caller-supplied and must be independently trusted**. The logged root/bundle SHA-256 values prove bytes only, not authenticity of the root. With explicit `--online`, `gh` uses its own built-in trust policy for public read-only GitHub API attestation lookup.
- An artifact filename/bytes change after verification, a wrong issuer/repository/workflow/ref/SHA, an unattested file, malformed output or altered bundle/root fails closed. The Rust CLI does not execute the downloaded artifact, run scanner binaries, fetch Git code or access private services.
- The dedicated scanner composition `inspect-attested-scan` first requires verified artifact origin, then validates the scanner report bytes against the verified artifact SHA-256 before parsing. Even a truly signed Trivy/OSV JSON **does not prove its actual scanner execution or complete coverage**; a clean report remains REVIEW only. The public tested fixture is a signed **binary**, so its scanner result is UNKNOWN.
- The R8 local release candidate is **not signed** by this change. No GitHub Actions CI, GitHub Release, crates.io publication, deployment, production data or privileged self-hosted runner is authorized.

## R10 local scan and signed-review trust boundaries

- **Default read-only:** review-upgrade can consume two existing bounded JSON files with no tool execution, Git network fetch or provider mutation. Without independently signed artifact evidence, a clean imported report remains UNKNOWN, not proof of scanner execution.
- **Executable OSV is explicit:** local-osv-lockfile intentionally invokes an owner-selected, SHA-256-pinned external OSV executable twice, against isolated Cargo.lock bytes extracted from exact local Git commits. Executable SHA-256 equality does NOT independently authenticate its publisher. The external executable is part of the trust boundary. It is invoked without inherited HOME/credentials, source hooks, Cargo runs or call analysis.
- **Public dependency metadata:** allow_public_osv_network must be set true explicitly. A public OSV API request can expose dependency names/versions. Do not scan private customer/source lockfiles until separately authorized. A local scanner process can have side effects beyond the Rust process's own controlled actions; do not run an untrusted external binary.
- **GH security gate:** known GitHub CLI attestation signer-workflow/source-ref vulnerabilities are fixed in gh 2.102.0. R10 refuses older, missing or malformed gh version output before any attestation verification. An exact signed file origin is not proof that a scanner ran or that its source DB is fresh.
- **No false green:** a persistent critical/advisory finding stays BLOCKED even with zero new findings; unknown/missing scanner source coverage is UNKNOWN, not zero. Signature and source commit mismatches are BLOCKED. The release, production and action authorization flags remain false.
- **Owner-private receipts:** only --evidence-dir writes the two raw reports and optional original Cargo.lock snapshots. Creates a new no-overwrite 0700 directory and 0600 files, SHA256SUMS integrity, not a signature. These files may reveal package names and original scanner paths; do not publish private scan outputs.

## R18 pinned OSV first use — explicit downloader and network consent

- `review-local --install-pinned-osv` **downloads a third-party executable** from an exact GitHub HTTPS release URL when the per-user cache does not already contain the pinned bytes. It validates the complete SHA-256 and expected byte length before running it; subsequent uses revalidate the cache. This is a byte-identity check, **not** independently verified publisher provenance.
- The public OSV network permission is separate: `--allow-public-osv-network` is required even when the pinned scanner is already cached. Dependency names and versions can be sent to public OSV services by that scanner. **Do not use the opt-in executable mode for private or sensitive dependencies without approval.**
- The cache is stored under a private per-user path and refuses final symlinks or unsafe writable cache directories. A separate process with sufficient local filesystem privileges may still pose a race or executable substitution threat; such local attackers are outside the current limited trust assurance. The Tredven archive does **not** redistribute the OSV-Scanner executable.
- The manual alternative is `--osv-bin FILE --osv-sha256 HEX` with `--allow-public-osv-network`. There is no Tredven telemetry, automatic Git checkout/clone, push, merge or deployment.

## R20 GitHub alpha artifact — source identity and authorization are separate

- The R20 GitHub workflow has only the manual `workflow_dispatch` trigger and an exact repository, owner-actor, repository-ID and `refs/heads/main` job gate. Its planned outputs are a signed build archive and short-lived Actions artifacts, **not** a GitHub Release, deployment or permission to use the binary in production.
- `scripts/verify_signed_alpha.py` delegates X.509/Sigstore verification to the official GitHub CLI with exact signer workflow, repository, source ref and source SHA policies, and refuses an unsigned local artifact. Offline-bundle verification has a repository-renaming limitation; online GitHub API verification is preferred for current repository identity.
- The static Linux musl archive carries both locked Rust dependency notices and the toolchain's runtime/musl notices. These are engineering completeness checks, not independent legal review or evidence of commercial distribution rights.
- Until a separately approved hosted workflow has run and its signature has been independently verified, **the actual GitHub-hosted signing path remains UNKNOWN / NOT RUN**.

## R11 signed CI run receipts — provenance versus process execution

- `review-upgrade` `signed-ci-receipt` delegates signature and trusted-root checks to a **patched GitHub CLI (2.102.0+)**. A signed receipt must match an independently owner-maintained exact signer repository ID, source ref/commit, workflow path, signed artifact filename/digest, GitHub-hosted runner and signed Actions run ID/attempt URI. The CI signer SHA is deliberately **not** assumed to equal the scanned third-party repository SHA.
- After verification, the receipt's **baseline and candidate source refs** must resolve to the exact local Git commit objects, and the original `Cargo.lock` byte hashes, original OSV JSON byte hashes and scanner-exit claims must match. Tampering, wrong target commits, wrong report bytes or mismatched run identity fails closed. The receipts are user-supplied and untrusted before GitHub verification.
- A GitHub-signed JSON receipt proves that a specific **workflow claimed** these results. Whether the scanner really executed and covered all intended dependencies additionally depends on reviewing the trusted workflow at the signed source commit and its execution environment. `scanner_execution_cryptographically_attested` and production/release/action authorization remain **false** pending independent qualification. An internally consistent unsigned receipt is **BLOCKED**, not REVIEW.
- The R11 workflow source exists **only as a manually dispatched reference** (`workflow_dispatch`), never `push`, `pull_request` or `schedule`. It uses a public reference source and the pinned OSV tool; running it will make PUBLIC GitHub API requests and publish an attestation/artifact. This code-development approval does not authorize a run or release. The external public scanner asset SHA and GitHub action SHA pins reduce substitution risk but do not replace independently authenticated publisher provenance.
- Owner-selected attestation bundle and trusted root must be separately trusted; `--online` is explicit and may query GitHub. No private Tredven lockfiles, credentials, deployments, Git merges, productions writes, or release actions are authorized. `--evidence-dir` creates new owner-private files only (0700 dir/0600 files); checksum manifests are not signatures.

## Report vulnerabilities

Use GitHub's private vulnerability reporting if enabled, or contact the project maintainers through the repository's security reporting channel. Do not publicly post exploit payloads with real user data.

## Non-goals

No background service, telemetry, credentials, arbitrary remote scripts, production mutations or guaranteed security verdicts. This project is not a security scanner or a production upgrade orchestrator.
