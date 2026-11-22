# R18 — Opt-in pinned OSV bootstrap and fully exercised local first use

2026-11-22. Canonical R17 base commit: `20475fccaad5561e7cf8a822c2f845046d6b24e3`. Local branch: `feat/r18-pinned-osv-bootstrap-20261122`.

## Value goal and ROI challenger

Usable capability: a developer who has an extracted Tredven Linux x86-64 archive and an existing local Git repository should no longer need to separately install the 58 MB OSV-Scanner or hand-enter a scanner SHA. One command obtains the exact upstream asset with user consent, verifies it, and runs the two-commit upgrade review. A repeated command reuses the verified binary.

Three viable approaches: (A) redistribute OSV inside each Tredven release (~58 MB per Linux platform plus broader redistribution attribution/integrity footprint); (B) require prior OSV installation and a manually copied digest (R17 already does this but has higher first-use friction); (C) explicitly download and pin the official OSV release to an isolated per-user cache, then reuse the existing engine. **Selected C**. No new scanning engine, HTTPS library, hosted services, billing, signers or orchestration.

## Scope, owner rights, and pin

- Exact release: `google/osv-scanner` v2.7.1, GitHub-hosted Linux amd64 asset `osv-scanner_linux_amd64`.
- Canonical upstream URL: `https://github.com/google/osv-scanner/releases/download/v2.7.1/osv-scanner_linux_amd64`.
- Asset SHA256 published on the actual GitHub release record: `fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8`.
- Exact expected size: **58,187,936 bytes**. Both size and SHA are compiled into the binary; they are checked before execution and on every reuse.
- Only **Linux x86-64** supported for managed download; other platforms still use the existing manually pinned `--osv-bin` and `--osv-sha256` path. The OSV binary is **not bundled** in the Tredven release archive.
- The new opt-in is `--install-pinned-osv`, which **also requires** `--allow-public-osv-network`; otherwise no bootstrap is attempted. Each scan retains its own public-OSV-network gate. Git clone/fetch is still user-managed.
- The path is `XDG_CACHE_HOME/tredven-upstream/tools/osv-scanner-v2.7.1-linux-amd64` (or HOME/.cache by default). Cache directories must be non-symlink, non-group-writable and non-world-writable. A custom XDG base must already exist. Created directories use 0700; downloaded files use 0700.
- The download uses the system `curl` with HTTPS-only initial/redirect protocols, timeout, size limit, and no inherited secret-bearing environment. Files are created privately, checked for digest and size, then installed without replacing an existing target; corrupted or symlinked cache entries fail closed.
- Source-path/tag resolution happens before a scanner download. Existing schema and source / scanner / evidence rules remain authoritative; no fork of the review engine.
- The exact digest is a *byte-identity pin derived from the GitHub release record*; it is not an independent Sigstore verification of the OSV publisher.

## Real independent E2E (public data only)

Repository: https://github.com/sharkdp/fd. Baseline `v10.4.2` commit `7027d45303b412be6fa9c09d689cc6276748fb38`, candidate `v10.5.2` commit `b2a287b3993768e0ec52f0852916917f23fb2a38`.

- **Fresh XDG cache:** real uncached GitHub asset download -> size and SHA validated -> run two OSV scans on the two actual Cargo.lock snapshots -> produce native report. **PASS**, total **6.235 s** in one local run (not a population statistic). Observed `REVIEW`, baseline 3 advisories, candidate 0, resolved 3, production/release authority false.
- **Warm cache:** exact same pinned binary reused without modification, `REVIEW`, same three resolved IDs, **2.17 s**. The file's modification time, size and mode were unchanged; cached SHA is verified in source on reuse.
- Public SHA for observed cached executable: `fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8`. The original R16 direct-OSV scans also agreed on 3/0 occurrences.
- Local ignored evidence path: `output/r18-cold-start-20261122/`, including `cache/`, `cold-run.stdout`, `cold-run.stderr`, `cold-run-metrics.json`, `evidence/review.json`, `warm-cache.md`.

## Red/green, negative, and safety validation

- New unit tests: pinned HTTPS URL/digest constant and refusal of wrong-length/unverified/symlinked cached bytes.
- New CLI negatives: implicit OSV network rejected; manual-scanner and pinned-bootstrap conflict rejected; invalid Git tag rejected before download; corrupted cache rejected without overwrite; duplicate opt-in rejected; symlinked XDG cache root rejected. **6/6 targeted tests PASS**.
- The pre-existing R17 manual binary+SHA flow is preserved as an explicit alternative. Missing network consent never triggers a download.
- Not yet proven: hosted signed GitHub Actions E2E; public trust of the unsigned local candidate; developer onboarding on an unprepared machine; macOS/Windows install; source publisher authenticity; external user value; any paid conversion.

## Acceptance / subsequent gate

Build the new committed R18 source with the existing R12 third-party license-annex release script and verify the archived binary, notices, checksum and actual cached public Git E2E from an extracted tarball. Commit the R18 branch locally only. No GitHub push, PR modification, merge, hosted scanner Actions dispatch, release, outreach or production change is approved.

## Complete project status

Overall PARTIAL. Functional readiness UNKNOWN (Delta UNKNOWN), integrated E2E readiness UNKNOWN (Delta UNKNOWN), production readiness UNKNOWN (Delta UNKNOWN) because there is no reproducible whole-project denominator and genuine hosted + external customer validation remain unproven. The isolated local first-use path is a proven narrow vertical, not the entire project.

Next best ROI after a verified archive: decide owner-controlled public signing/distribution qualification, then one genuine independent OSS developer install/use comparison against OSV + Renovate. Avoid adding a hosted billing plane before real multi-user needs are shown.
