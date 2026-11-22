#!/usr/bin/env bash
# R22 read-only public-data first-use rehearsal. This does NOT sign or release.
set -euo pipefail
usage() {
  cat >&2 <<'USAGE'
Usage: bash scripts/r22_cleanroom.sh --candidate-dir LOCAL_RC_DIRECTORY --archive-sha256 EXACT_HEX --output-name UNIQUE_NAME --allow-public-network --allow-unsigned-local-candidate
Tests a local unsigned static Linux alpha in a fresh Debian 12 container.
Explicit flags authorize Docker Hub/Debian apt/GitHub fd/OSV public traffic and local UNSIGNED binary execution as a developer test ONLY.
Never use this as proof of official artifact publisher authenticity, external user success or a production release.
USAGE
  exit "${1:-2}"
}
repo="$(cd "$(dirname "$0")/.." && pwd -P)"
candidate=''
sha=''
outname=''
network=0
unsigned=0
while (( $# > 0 )); do
  case "$1" in
    --help|-h) usage 0;;
    --candidate-dir)
      (( $# >= 2 )) || usage
      [[ -z "$candidate" ]] || usage
      candidate="$2"; shift 2;;
    --archive-sha256)
      (( $# >= 2 )) || usage
      [[ -z "$sha" ]] || usage
      sha="$2"; shift 2;;
    --output-name)
      (( $# >= 2 )) || usage
      [[ -z "$outname" ]] || usage
      outname="$2"; shift 2;;
    --allow-public-network)
      (( network == 0 )) || usage
      network=1; shift;;
    --allow-unsigned-local-candidate)
      (( unsigned == 0 )) || usage
      unsigned=1; shift;;
    *) usage;;
  esac
done
[[ "$network" == 1 && "$unsigned" == 1 ]] || usage
[[ "$sha" =~ ^[a-f0-9]{64}$ ]] || usage
[[ "$outname" =~ ^[A-Za-z0-9_-]{1,80}$ ]] || usage
[[ "$candidate" = /* && -d "$candidate" && ! -L "$candidate" ]] || usage
for cmd in podman python3 sha256sum stat; do
  command -v "$cmd" >/dev/null || { echo "R22_MISSING_PREREQUISITE: $cmd" >&2; exit 2; }
done
archive="$candidate/tredven-upstream-v0.1.0-x86_64-unknown-linux-musl.tar.gz"
[[ -f "$archive" && ! -L "$archive" ]] || { echo R22_LOCAL_ARCHIVE_MISSING >&2; exit 2; }
actual="$(sha256sum "$archive" | cut -d' ' -f1)"
[[ "$actual" == "$sha" ]] || { echo R22_LOCAL_ARCHIVE_SHA256_MISMATCH >&2; exit 2; }
# Existing release-candidate verifier remains authoritative for exact contents,
# runtime license notices, Cargo.lock derived notices and no-release authority.
python3 -I -B "$repo/scripts/release_candidate.py" verify --dir "$candidate"
out="$repo/output/$outname"
[[ ! -e "$out" && ! -L "$out" ]] || { echo R22_OUTPUT_EXISTS_NO_OVERWRITE >&2; exit 2; }
install -d -m 700 "$out"
install -d -m 700 "$out/evidence"
echo R22_BUILD_LOCAL_DEBIAN12_IMAGE_AFTER_EXPLICIT_PUBLIC_CONSENT
podman build --network=pasta --pull=missing -f "$repo/tests/cleanroom/Containerfile" \
  -t localhost/tredven-r22-debian12-test:local "$repo/tests/cleanroom"
echo R22_RUN_REAL_PUBLIC_GIT_AND_OSV_AS_NON_PRIVILEGED_USER
podman run --rm --pull=never --network=pasta --security-opt=no-new-privileges \
  -v "$repo/tests/cleanroom:/pilot:ro,Z" \
  -v "$candidate:/input:ro,Z" \
  -v "$out/evidence:/results:rw,Z" \
  --entrypoint /bin/sh localhost/tredven-r22-debian12-test:local -c "
set -eu
mkdir -p /tmp/r22-user
install -m 0600 /input/tredven-upstream-v0.1.0-x86_64-unknown-linux-musl.tar.gz /tmp/r22-user/candidate.tar.gz
install -m 0600 /pilot/first_use.py /tmp/r22-user/first_use.py
chown -R nobody:nogroup /tmp/r22-user
su -s /bin/sh nobody -c 'env HOME=/tmp/r22-user XDG_CACHE_HOME=/tmp/r22-user/.cache R22_CANDIDATE_SHA256=$sha R22_EXPLICIT_PUBLIC_OSV_REHEARSAL=yes python3 /tmp/r22-user/first_use.py' >/tmp/r22-console.log 2>&1 || {
  cat /tmp/r22-console.log
  cp /tmp/r22-user/evidence/* /results/ 2>/dev/null || true
  exit 9
}
cat /tmp/r22-console.log
cp /tmp/r22-user/evidence/* /results/
"
echo R22_CLEANROOM_EVIDENCE_PATH="$out/evidence"
echo R22_CLEANROOM_COMPLETED_LOCAL_REHEARSAL_ONLY
