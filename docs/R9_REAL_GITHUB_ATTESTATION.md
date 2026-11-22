# R9 — Real GitHub/Sigstore attestation verification in Rust

**Date:** 2026-11-22
**Branch:** feat/verified-github-attestation-r9-20261122, based on R8 commit 046a62c77d6a58894d0848ee6c204572650e115a
**Scope:** Public MIT Rust CLI only. No private Tredven source, server, customer data, GitHub release, merge, production deployment or own-system E2E.

## Decision and user capability

The Rust CLI now delegates real cryptographic verification of a **locally available artifact and signed attestation** to the official GitHub CLI, then applies exact, restrictive source identity policy. No in-house DSSE/Fulcio/Rekor cryptography and no new Rust crates.

Two user-visible commands:
- **verify-attestation** — checks the artifact signature/bundle, official trusted root, immutable GitHub repository ID, exact signer workflow, source ref/tag and source commit, signed artifact subject name and SHA-256, SLSA predicate, GitHub-hosted runner and verified timestamp.
- **inspect-attested-scan** — performs the same signature check, then parses the exact artifact bytes as existing Trivy JSON v2 or OSV-Scanner v2. A signed non-scanner binary produces scanner status UNKNOWN; a clean signed scanner JSON only produces REVIEW, not READY. **The signature does not independently prove the scanner executed.**

Run in offline mode with the example operator policy, after downloading the public signed fixture below:

~~~bash
cargo run --locked -- verify-attestation \
  --artifact output/r9-public-signed-fixture/rust_template-0.1.0-linux-amd64 \
  --policy examples/r9-public-attestation-policy.example.json
~~~

For a genuinely signed scanner JSON (not supplied as a public fixture in this project), use:

~~~bash
cargo run --locked -- inspect-attested-scan \
  --artifact /absolute/path/to/signed-trivy-report.json \
  --policy /absolute/path/to/owner-maintained-policy.json \
  --scanner trivy-json-v2 \
  --subject 'EXACT_TRIVY_ArtifactName'
~~~

The same commands support explicit manual --repo, --repo-id, --signer-workflow, --source-ref, --source-commit, --bundle, --trusted-root, --predicate-type flags. Offline is the default; without both bundle and trusted root, verification BLOCKS. Alternatively use **--online** instead of the bundle/root fields for explicit read-only public GitHub API lookup. An operator policy can also explicitly request online mode. Mixed policy and ad-hoc identity overrides are rejected.

The JSON policy can be reused, avoiding repeated long terminal argument lists. Policy file and evidence paths are bounded, normal non-symlink files. Relative bundle/root paths are resolved relative to the policy file. **Keep the trusted policy independently owner-maintained: never trust arbitrary policy JSON from the untrusted artifact repository.**

## Authentic public signed fixture — actual 2026-11-22 evidence

The example uses an existing, actually signed **third-party binary**, not an invented or self-signed scanner result:

- Repository: https://github.com/attested-delivery/rust-template
- Release: v0.1.0, asset rust_template-0.1.0-linux-amd64, 337,512 bytes.
- Artifact SHA-256: e5bb76a3dcfb7faba7306c623326b8e590f023a41649e974935c41bf097475ea.
- Immutable repository ID: 1273337322 (checked via GitHub API).
- Certificate signer SAN: https://github.com/attested-delivery/rust-template/.github/workflows/release.yml@refs/tags/v0.1.0
- Exact source commit: 2b97f20f71e2b6d9c3f23ea7e968b7dd26d97e6a.
- SLSA predicate: https://slsa.dev/provenance/v1, GitHub-hosted runner, one verified trusted timestamp.
- Two attestations were initially returned for this same digest by a broad lookup, including another branch identity. Strict workflow/ref/commit filtering selected the exact release-tag attestation; a generic green claim without this policy would be weaker.
- The actual GitHub CLI **online verification PASS**, and the original downloaded bundle plus public trusted roots **offline verification PASS**. The Rust wrapper itself also passed both.
- Official root output at this verification had SHA-256 65ca537f6ed8a47fd0e560c421baa1f6c1efb8b25fc200d8c5c02c0e92eb2b9c. Root content can rotate; **its hash alone does not attest to its independent origin**.
- The real third-party executable was downloaded **but never run**, signed fixture bytes were not copied to the MIT public repository.

To reproduce, from the Rust repository root:

~~~bash
mkdir -p output/r9-public-signed-fixture
gh release download v0.1.0 \
  --repo attested-delivery/rust-template \
  --pattern 'rust_template-0.1.0-linux-amd64' \
  --dir output/r9-public-signed-fixture

(cd output/r9-public-signed-fixture && \
 gh attestation download rust_template-0.1.0-linux-amd64 \
 --repo attested-delivery/rust-template \
 --predicate-type https://slsa.dev/provenance/v1)

gh attestation trusted-root > output/r9-public-signed-fixture/trusted_root.jsonl
gh api repos/attested-delivery/rust-template --jq .id

cargo run --locked -- verify-attestation \
  --artifact output/r9-public-signed-fixture/rust_template-0.1.0-linux-amd64 \
  --policy examples/r9-public-attestation-policy.example.json

# Run optional real cryptographic verification integration tests:
TREDVEN_R9_PUBLIC_FIXTURE_DIR="$PWD/output/r9-public-signed-fixture" \
  cargo test --locked --test attestation_cli
~~~

These downloads use the public GitHub API, not any Tredven user system. In a future fully offline run, only the already downloaded artifact, bundle, trusted root and installed GH verifier are needed.

## Trust boundaries and real falsification

**Verified:** The external official GH binary cryptographically accepted the exact signed artifact, signature identity and trusted timestamp. Rust additionally restricted and checked the immutable GitHub repository ID, signer SAN, source ref+digest, subject filename+digest and runner. Offline bundle SHA-256 and caller-supplied root SHA-256 are recorded. No raw scanner secret matches or signed predicate descriptions are exposed.

**Not verified:** That a scanner ran, that its vulnerability database was fresh, that scan coverage was complete, that Tredven's local unsigned R8 candidate became signed, remote deployment compatibility, production safety, buyer value or the provenance of an **operator-supplied** offline root. A malicious custom root plus matching forged attestation could be self-consistent. Online verification delegates root selection to the official GH tool. The trusted GH CLI binary itself is part of the trusted computing base. Immutable repo-ID comparison mitigates ambiguous repository name reuse during offline verification.

**Denial tests against the real public signed fixture:**
- Modifying the signed artifact bytes → BLOCKED.
- Wrong immutable repository ID → BLOCKED, even when GitHub verifies a real signature.
- Wrong signer workflow, tag or source commit → BLOCKED.
- Missing/invalid trusted root or modified attestation bundle → BLOCKED, never online fallback.
- Rename artifact but keep identical signed bytes → BLOCKED (signed subject name mismatch).
- Try to verify unsigned local Tredven R8 binary with an unrelated third-party attestation → BLOCKED.
- Treat the valid signed release executable as Trivy JSON → signature VERIFIED but scanner status UNKNOWN, no false scanner PASS.
- Invalid source SHA, symlinked artifact or policy file, mixed online/offline policy overrides → rejected.
- A valid owner-maintained reusable JSON policy was verified against the real signed sample.

Only the actual GH verifier establishes cryptographic signature validity. Pure unit tests for JSON field matching are post-verification logic checks, **not cryptographic proofs**.

Exit codes: verify-attestation 0 = signed provenance VERIFIED only; 2 = BLOCKED; 1 = bad argument. inspect-attested-scan 0 = signed artifact and scanner review only; 2 = signature or scan BLOCKED; 3 = authentic artifact with scanner UNKNOWN; 1 = bad argument. The tool always reports **production_ready=false, release_authorized=false, action_authorized=false, scanner_execution_verified=false**.

## ROI Challenger

- **Custom Rust crypto / DSSE validator:** rejected, unsafe duplication of established Sigstore/GH software.
- **Immediate public release / GitHub Actions signing:** rejected, unapproved workflow execution and release/publish scope.
- **More proprietary static SQL or scanner rules:** rejected, low incremental value and likely OSS duplication.
- **Selected:** genuine signed public sample plus the official verifier, strict origin policies and optional scanner parsing in existing Rust CLI, with no new crates. This changes an evidence provenance capability instead of creating another self-declared PASS flag.
- **Defer:** only if a genuinely signed fixture could not be found. Actual signed sample was found and verified; thus no deferral needed.

Official primary docs:
- https://cli.github.com/manual/gh_attestation_verify
- https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline
- https://docs.github.com/en/actions/concepts/security/artifact-attestations
- https://docs.sigstore.dev/cosign/verifying/verify/
- https://attested-delivery.github.io/docs/tutorials/verify-your-first-attested-release/

**Whole-project readiness:** functional UNKNOWN (Δ UNKNOWN: no denominator across all planned features); integrated E2E UNKNOWN (Δ UNKNOWN: signed scanner JSON and live scanner-to-source proof not present); production UNKNOWN (Δ UNKNOWN: no approved release or deployment). R9 signed-artifact verification slice COMPLETED on third-party public signed data; full Rust OSS product PARTIAL, paid SaaS value NOT PROVEN.

## Final R9 local acceptance — executed (not conjectured)

- Fedora pinned Rust 1.100.0; all-target test groups: **53 + 0 + 15 + 6 + 10 + 10 + 27 + 7 = 128/128 PASS**, with the authentic public signed fixture explicitly enabled via TREDVEN_R9_PUBLIC_FIXTURE_DIR. The **15 attestation CLI integration tests include real GitHub signature validation**, plus actual manipulated bundles, signer identity, root and local unsigned R8 denial. Without that optional fixture directory, those specific public-repository tests intentionally skip public downloads; do not interpret a no-fixture test PASS as a real cryptographic qualification.
- Rustfmt check PASS; Clippy with locked all-targets -D warnings PASS; optimized Cargo release-profile build PASS (approximately 1.1 MB locally). No additional Cargo dependencies added.
- Strict exact-policy verification PASS using the release-profile Rust binary was executed separately after build; the output maintains signature_verified=true only for the genuine sample and production_ready=false.
- Neither real signed fixture nor trusted roots are committed to the public MIT repository; their hashes and acquisition instructions are provided, stored only in ignored local output/. No production or private Tredven environment used.

**Next best ROI:** Only after obtaining an **actually signed Trivy/OSV JSON file** from a trusted workflow, verify its certificate and execution provenance in this Rust path. Until then, avoid more homegrown crypto/frameworks. User explicitly deferred private Tredven-system validation.
