# R17 — Open Source Product Direction and Local First-Use Gate

Date: 2026-11-22. This is a product direction, **not** evidence of paid demand or a commercial launch.

## Product thesis

**Tredven Upstream — Know what changes before you upgrade.**

The job is to translate a version-to-version source and dependency change into an **explainable, byte-linked upgrade-review decision**. It is not another vulnerability database, package-manager bot, or production deployment tool. The default is local-first, read-only and permission-minimal.

## What is in-scope

- A free OSS core (existing MIT license) that remains useful without signup, SaaS, telemetry or licence key.
- Local source/tag/lockfile comparison, strict scanner input and report hashes, actionable new/resolved advisories, explicit unknowns and bounded evidence.
- Opt-in GitHub Actions verification of already-signed attestations without inventing cryptography or treating a signature as permission to deploy.
- Native ecosystem tools stay independent upstream dependencies: OSV-Scanner and Renovate/Dependabot already solve discovery and remediation. Reuse them rather than building a parallel scanner.
- Early developer experience: one documented CLI command for a locally cloned Rust repo, with required explicit public-network approval and SHA-pinned OSV binary. No auto-download or source-code execution.

## Potential paid layer, contingent on actual use

1. Multi-repository hosted workspace and change history with retention controls.
2. Team review/approval and audit evidence export, preserving human ownership of merge/deploy.
3. Multi-project alerts, policy inheritance and integrations, without a public repo access requirement.
4. Paid operation/support for private/on-prem deployments, while retaining a capable free CLI.

These are **candidate** features. They are NOT built, validated, committed to as paid entitlements, or individually priced. Do not strip existing MIT-licensed core features to force conversion. A separate service or licensed extension needs separately maintained intellectual property rights and third-party licensing review; the MIT permissions already granted cannot be retroactively withdrawn from published source.

## ROI challenger — before choosing the next work slice

| Option | User value | Critical drawback | Decision |
| --- | --- | --- | --- |
| Launch billing/dashboard now | Possible future revenue | No hosted customer value, user identity or demand evidence | Defer |
| Expand scanner adapters/ecosystems | Wider coverage | OSV-Scanner and Renovate already cover much of this | Defer |
| Merge the hosted GitHub workflow now | Real signature proof | Requires owner approval and no guarantee users can install the CLI | Keep gated |
| Integrate existing R12 notices and remove first-use JSON friction | Immediately lowers OSS adoption friction | Local Rust/OSV binaries still prerequisites | **R17 selected** |

## Technical acceptance — R17

- Reuse the actual R12 offline license-annex generator. Any missing Cargo registry dependency notice fails the release build; local candidate archive contains `LICENSE`, `README.md`, `THIRD_PARTY_NOTICES.txt` and a native Rust binary.
- First-use command: `review-local --repo DIR --from TAG --to TAG --osv-bin FILE --osv-sha256 HEX --allow-public-osv-network [--format ...]`. It delegates to the **existing** schema validator and review engine; no second scanner or evidence parser.
- Network is opt-in, scanner is SHA-pinned, repository must be an existing local Git clone, owner data does not go to a Tredven service, no git mutation, no workflow dispatch.
- Actual independent public `sharkdp/fd` v10.4.2 -> v10.5.2: three RUSTSEC advisory occurrences resolved, **REVIEW** not green, full human-visible identity list.
- A local release archive is **not** a signed GitHub Release and cannot grant authority to distribute or run production. Release and external trial stay owner-gated.

## Market and licensing reference — verified public sources

- OSV-Scanner Apache-2.0; native license scanning and guided remediation: https://github.com/google/osv-scanner ; https://google.github.io/osv-scanner/usage/license-scanning/
- Mend Renovate free CLI and Community, paid Enterprise: https://www.mend.io/renovate/ ; https://docs.mend.io/renovate/latest
- Socket paid team/business tiers and a free tier: https://socket.dev/pricing
- Snyk freemium/paid tooling: https://snyk.io/plans/

**No market inference** from these examples: existing paid security tooling shows that an OSS+paid model is plausible, NOT that Tredven can command a similar price, demand, revenue or category share.

## Next real adoption measurement

Run a genuine independent developer first-use study on a public project: measure installation effort, number of copy/paste commands, human time-to-decision and clarity versus native OSV-Scanner, with exact versions and reproducible inputs. No private customer dataset, outreach, invoices, merge or public release without separate owner approval.

## Overall readiness and owner gates

Product-functional readiness: UNKNOWN (no full roadmap denominator); integrated hosted E2E: UNKNOWN (the public-data local path is not hosted signed CI); production/paid readiness: UNKNOWN (no paid accounts, entitlement enforcement, hosted secure workspace or customer validation). Deltas UNKNOWN. Status PARTIAL; no public push/merge/deploy or owner-gated workflow dispatch in R17.
