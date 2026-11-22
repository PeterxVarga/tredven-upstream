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

## Report vulnerabilities

Use GitHub's private vulnerability reporting if enabled, or contact the project maintainers through the repository's security reporting channel. Do not publicly post exploit payloads with real user data.

## Non-goals

No background service, telemetry, credentials, arbitrary remote scripts, production mutations or guaranteed security verdicts. This project is not a security scanner or a production upgrade orchestrator.
