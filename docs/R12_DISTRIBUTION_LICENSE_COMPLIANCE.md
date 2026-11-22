# R12 — Offline distribution license qualification

Scope: feat/distribution-license-compliance-r12-20261122, based on public
R11 commit 286814b74b8439eb883fcd276c07cf94bbbc3745.
**Local feature branch only; no push, merge, GitHub Release, CI dispatch or deployment.**

## Decision and ownership

The **entire R11 branch is already publicly accessible under MIT**. This
includes the source on the public feature branch, not just main. R12 does not
claim that published MIT rights can be withdrawn or that a differently licensed
paid product already exists. Keep the independent free CLI permissively licensed
for now; a future managed service or closed extension needs its own source,
ownership, distribution and customer-demand qualification.

## Release-candidate qualification

The scripts/release_candidate.py build remains a **fully offline** local operation
that requires a clean commit, pinned Rust, cached dependencies and passing tests.
It now fails closed unless cargo metadata --locked --offline matches **every**
registry crate in the exact Cargo.lock. It reads actual registry-source
license/notice files, not a manually transcribed or guessed set of license
strings. The binary tarball contains THIRD_PARTY_NOTICES.txt with package
versions, declared license expressions, original Cargo.lock SHA-256 and all
available top-level LICENSE/LICENCE/NOTICE/COPYING/COPYRIGHT/UNLICENSE files.
A missing source crate or license notice blocks generation.

The new local candidate schema is **v2**, requiring and checking the annex's
SHA-256 even if an attacker rehashes the outer archive and manifest. Legacy v1
release candidates are intentionally **not accepted** by the updated verifier.
The checksums prove local consistency, **not authenticity, legal sufficiency,
or authorization to ship**. The license annex conservatively covers every
locked external crate, even build-time dependencies.

For this R11 Cargo.lock the annex covers 21 packages and includes
unicode-ident's Unicode text and memchr's Unlicense/MIT files.
One previously missing public libc 0.2.191 crate was fetched separately
using cargo fetch --locked into an isolated Cargo cache to enable offline
metadata and build; no network call is made inside release-candidate build.
The Rust runtime toolchain and Cargo caches remain isolated under
~/fedora-30g/toolchains/tredven-rust.

## Remaining external distribution/data rights

The actual local candidate tarball contains only the Tredven Rust executable,
the Tredven LICENSE, README.md and third-party license annex. It **does not
bundle** the OSV-Scanner, gh, Witness, Chainloop, or their datasets, so this
annex does not certify redistribution of those tools or vulnerability records.
If a future release embeds those binaries or republishes vulnerability records,
check the exact source version, redistribution/attribution terms, provenance
and restrictions separately. Current checks are engineering gates, not legal advice.

R11 signed CI scanner-run execution and production readiness remain unproven;
no external attestation, signature, customer outcome, or production permission
is implied by passing offline tests.

## Reproduce

With the isolated Cargo environment on the authorized Fedora machine:

~~~sh
export CARGO_HOME="$HOME/fedora-30g/toolchains/tredven-rust/cargo"
export RUSTUP_HOME="$HOME/fedora-30g/toolchains/tredven-rust/rustup"
export CARGO_TARGET_DIR="$HOME/fedora-30g/toolchains/tredven-rust/target-upstream"
export PATH="$CARGO_HOME/bin:$PATH"
python3 -B -m unittest scripts/test_release_candidate.py -v
python3 -I -B scripts/release_candidate.py build --out "$PWD/output/r12-local-rc"
python3 -I -B scripts/release_candidate.py verify --dir "$PWD/output/r12-local-rc"
~~~

The build command is **not compatible with a dirty working tree**, and the
output path must be new: both are intentional non-publishing safety gates.
