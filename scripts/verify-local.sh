#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
python3 -I -B scripts/test_release_candidate.py
echo "LOCAL_RUST_UNIT_CLI_ONLY_PASS; no live source check or production grant"
