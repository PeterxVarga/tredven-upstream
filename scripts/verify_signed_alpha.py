#!/usr/bin/env python3
"""Strict, GitHub-native verification of an R20 signed *candidate* archive.

This delegates cryptography to the installed official gh CLI. It does NOT
sign software, publish a release, or authorize a production deployment.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

REPO = "PeterxVarga/tredven-upstream"
SIGNER = "PeterxVarga/tredven-upstream/.github/workflows/r20-manual-alpha-provenance.yml"
REF = "refs/heads/main"
EXPECTED_TARGET = "x86_64-unknown-linux-musl"


class Blocked(Exception):
    pass


def bounded_file(path: Path, limit: int) -> bytes:
    try:
        st = path.lstat()
        if not path.is_file() or path.is_symlink() or not 0 < st.st_size <= limit:
            raise Blocked("FILE_IS_MISSING_SYMLINK_OR_OUT_OF_BOUNDS")
        return path.read_bytes()
    except OSError as err:
        raise Blocked("UNREADABLE_VERIFICATION_INPUT") from err


def run_checked(cmd: list[str], timeout: int = 60) -> bytes:
    try:
        p = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as err:
        raise Blocked("VERIFIER_PROCESS_UNAVAILABLE") from err
    if p.returncode != 0:
        # Avoid leaking the entire GH environment or untrusted stderr into reports.
        raise Blocked("GITHUB_ATTESTATION_OR_CANDIDATE_VERIFICATION_FAILED")
    return p.stdout


def verify(directory: Path, bundle: Path | None, gh: str) -> dict:
    # Use the existing owner-reviewed exact-byte local candidate verifier.
    # Do not copy or reimplement its archive/hash, legal-notice or schema gates.
    rc_path = Path(__file__).resolve().parent / 'release_candidate.py'
    raw = run_checked([sys.executable, '-I', '-B', str(rc_path),
                       'verify', '--dir', str(directory)], timeout=40)
    try:
        local = json.loads(raw)
        manifest = json.loads(bounded_file(directory / 'manifest.json', 65536))
    except (ValueError, KeyError, TypeError) as err:
        raise Blocked("INVALID_CANDIDATE_RECEIPT") from err
    if (local.get('result') != 'LOCAL_RC_VERIFIED_UNATTESTED_NO_RELEASE'
        or local.get('source_commit') != manifest.get('source_commit')
        or manifest.get('target') != EXPECTED_TARGET
        or manifest.get('publication_authorized') is not False
        or manifest.get('production_ready') is not False):
        raise Blocked("UNEXPECTED_CANDIDATE_SOURCE_OR_AUTHORITY")
    sha = manifest['source_commit']
    if not isinstance(sha, str) or not re.fullmatch(r'[a-f0-9]{40}', sha):
        raise Blocked("INVALID_SOURCE_COMMIT")
    archive = directory / manifest['artifacts']['archive']['filename']
    archive_bytes = bounded_file(archive, 20 * 1024 * 1024)
    archive_sha = hashlib.sha256(archive_bytes).hexdigest()
    digest = manifest['artifacts']['archive']['sha256']
    if archive_sha != digest:
        raise Blocked("ARCHIVE_HASH_MISMATCH")
    gh_path = Path(gh)
    if not gh_path.is_absolute() or not gh_path.is_file() or gh_path.is_symlink():
        raise Blocked("QUALIFIED_GH_BINARY_REQUIRED")
    version = run_checked([str(gh_path), '--version'], timeout=10).decode('utf-8', 'replace')
    found = re.search(r'^gh version (\d+)\.(\d+)\.', version, re.MULTILINE)
    if found is None or tuple(map(int, found.groups())) < (2, 105):
        raise Blocked("GH_VERSION_UNQUALIFIED_FOR_SIGNED_ALPHA")
    cmd = [str(gh_path), 'attestation', 'verify', str(archive),
           '--repo', REPO, '--signer-workflow', SIGNER,
           '--source-ref', REF, '--source-digest', sha,
           '--deny-self-hosted-runners', '--format', 'json']
    if bundle is not None:
        bounded_file(bundle, 2 * 1024 * 1024)
        cmd.extend(['--bundle', str(bundle)])
    try:
        verified = json.loads(run_checked(cmd, timeout=80))
    except (json.JSONDecodeError, UnicodeError) as err:
        raise Blocked("INVALID_VERIFIED_GH_OUTPUT") from err
    if not isinstance(verified, list) or len(verified) == 0:
        raise Blocked("NO_VERIFIED_GITHUB_ATTESTATION")
    return {
        "schema": "tredven.upstream.signed-alpha-verification.v1",
        "result": "GITHUB_SIGNED_ARCHIVE_VERIFIED_NOT_A_RELEASE_GRANT",
        "artifact_sha256": archive_sha,
        "source_commit": sha,
        "repository": REPO,
        "signer_workflow": SIGNER,
        "source_ref": REF,
        "verification_mode": "local_bundle_name_binding_only" if bundle else "github_api_online",
        "signature_verified": True,
        "release_authorized": False,
        "production_ready": False,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--dir', type=Path, required=True, help='Exactly four local release candidate files')
    ap.add_argument('--bundle', type=Path, help='Optional downloaded Sigstore bundle; online GitHub API is preferred')
    ap.add_argument('--gh', default=shutil.which('gh'), help='Absolute path to trusted GitHub CLI >=2.105')
    args = ap.parse_args()
    try:
        if not args.gh:
            raise Blocked("QUALIFIED_GH_BINARY_REQUIRED")
        result = verify(args.dir, args.bundle, args.gh)
    except (Blocked, ValueError, KeyError, TypeError) as err:
        print('BLOCKED_SIGNED_ALPHA:' + str(err)[:180], file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
