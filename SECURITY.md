# Security

**Pre-alpha / source-only prototype.** Tredven Upstream does not access a live upstream, cluster, Docker socket, production database or credentials. It does not grant operational authority.

## Data handling

- Use only sanitized manifests. This tool accepts a local file or stdin and prints a local report; it does not upload data.
- **Do not submit secrets, internal endpoints or customer records** in GitHub issues, bug reports, examples or pull requests.
- The caller supplies all evidence and may lie; `source_verified` does not represent cryptographic verification.
- `BLOCKED` means stop and inspect. `REVIEW` and `UNKNOWN` also do not mean safe to deploy.
- Exit code 0 means the CLI ran successfully, **not that an upgrade is authorized**.

## Report vulnerabilities

Use GitHub's private vulnerability reporting if enabled, or contact the project maintainers through the repository's security reporting channel. Do not publicly post exploit payloads with real user data.

## Non-goals

No background service, telemetry, credentials, arbitrary remote scripts, production mutations or guaranteed security verdicts. This project is not a security scanner or a production upgrade orchestrator.
