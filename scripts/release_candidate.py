#!/usr/bin/env python3
"""Build or check an OFFLINE, untrusted/local Rust release candidate.

This is NOT a GitHub release, a signed attestation or permission to deploy.
No network or provider calls; the build requires cached Rust crates.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tomllib

SCHEMA = "tredven.upstream.local-release-candidate.v2"
NAME = "tredven-upstream"
MAX_BYTES = 20 * 1024 * 1024
HEX_SHA = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")


class InvalidCandidate(Exception):
    pass


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def regular_file(path: Path, limit: int = MAX_BYTES) -> bytes:
    st = path.lstat()
    if not path.is_file() or path.is_symlink() or st.st_size <= 0 or st.st_size > limit:
        raise InvalidCandidate("NOT_BOUNDED_REGULAR_NON_SYMLINK_FILE")
    return path.read_bytes()


def json_bytes(obj: dict) -> bytes:
    return (json.dumps(obj, sort_keys=True, ensure_ascii=True, indent=2) + "\n").encode()


def archive_bytes(binary: bytes, license_bytes: bytes, readme: bytes, notices: bytes,
                  runtime_notices: bytes | None = None) -> bytes:
    """Tar/gzip metadata are fixed so unchanged bytes get the same archive SHA."""
    stream = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=0, compresslevel=9) as gz:
        with tarfile.open(fileobj=gz, mode="w|", format=tarfile.GNU_FORMAT) as tf:
            members = [
                ("bin/tredven-upstream", binary, 0o755),
                ("LICENSE", license_bytes, 0o644),
                ("README.md", readme, 0o644),
                ("THIRD_PARTY_NOTICES.txt", notices, 0o644),
            ]
            if runtime_notices is not None:
                members.append(("RUST_RUNTIME_NOTICES.html", runtime_notices, 0o644))
            for name, raw, mode in members:
                member = tarfile.TarInfo(name)
                member.size = len(raw)
                member.mode = mode
                member.mtime = member.uid = member.gid = 0
                member.uname = member.gname = ""
                tf.addfile(member, io.BytesIO(raw))
    return stream.getvalue()


def write_candidate(dest: Path, *, binary: bytes, crate: bytes,
                    license_bytes: bytes, readme: bytes, notices: bytes, source_commit: str,
                    version: str, target: str, rustc: str, cargo: str,
                    runtime_notices: bytes | None = None) -> dict:
    if dest.exists() or dest.is_symlink():
        raise InvalidCandidate("OUTPUT_EXISTS_NO_OVERWRITE")
    if not GIT_SHA.fullmatch(source_commit) or not re.fullmatch(r"[0-9A-Za-z._+-]{1,48}", version):
        raise InvalidCandidate("INVALID_SOURCE_IDENTITY")
    if not re.fullmatch(r"[a-z0-9_-]{4,80}", target):
        raise InvalidCandidate("INVALID_RUST_TARGET")
    if (len(binary) > MAX_BYTES or len(crate) > MAX_BYTES or
        not binary or not crate or not notices or len(notices) > MAX_BYTES):
        raise InvalidCandidate("SOURCE_OR_BINARY_OUT_OF_BOUNDS")
    is_musl = target == "x86_64-unknown-linux-musl"
    if is_musl:
        if (not runtime_notices or len(runtime_notices) > MAX_BYTES
            or b"musl libc" not in runtime_notices):
            raise InvalidCandidate("MUSL_RUST_RUNTIME_LICENSE_NOTICES_REQUIRED")
    elif runtime_notices is not None:
        raise InvalidCandidate("RUST_RUNTIME_NOTICES_ONLY_QUALIFIED_FOR_MUSL")
    dest.mkdir(mode=0o700, parents=False, exist_ok=False)
    archive_name = f"{NAME}-v{version}-{target}.tar.gz"
    crate_name = f"{NAME}-{version}.crate"
    archive = archive_bytes(binary, license_bytes, readme, notices, runtime_notices)
    artifact_info = {
        "archive": {"filename": archive_name, "sha256": sha(archive)},
        "crate": {"filename": crate_name, "sha256": sha(crate)},
        "binary_in_archive_sha256": sha(binary),
        "third_party_notices_in_archive_sha256": sha(notices),
    }
    if runtime_notices is not None:
        artifact_info["rust_runtime_notices_in_archive_sha256"] = sha(runtime_notices)
    manifest = {
        "schema": SCHEMA,
        "name": NAME,
        "version": version,
        "source_commit": source_commit,
        "target": target,
        "rustc": rustc,
        "cargo": cargo,
        "build_profile": "release",
        "cargo_locked_offline": True,
        "tests_required": True,
        "artifacts": artifact_info,
        "signature_verified": False,
        "source_publisher_attested": False,
        "scanner_execution_attested": False,
        "production_ready": False,
        "publication_authorized": False,
        "status": "LOCAL_RC_UNATTESTED_NO_RELEASE",
    }
    manifest_raw = json_bytes(manifest)
    files = {
        archive_name: archive,
        crate_name: crate,
        "manifest.json": manifest_raw,
    }
    for name, raw in files.items():
        out = dest / name
        with out.open("xb") as f:
            f.write(raw)
        out.chmod(0o600)
    sums = "".join(f"{sha(raw)}  {name}\n" for name, raw in sorted(files.items()))
    sums_path = dest / "SHA256SUMS"
    with sums_path.open("xb") as f:
        f.write(sums.encode())
    sums_path.chmod(0o600)
    return manifest


def verify_candidate(dest: Path) -> dict:
    if dest.is_symlink() or not dest.is_dir():
        raise InvalidCandidate("NOT_A_NORMAL_CANDIDATE_DIRECTORY")
    m = json.loads(regular_file(dest / "manifest.json", 64 * 1024))
    if (set(m) != {
        "schema","name","version","source_commit","target","rustc","cargo",
        "build_profile","cargo_locked_offline","tests_required","artifacts",
        "signature_verified","source_publisher_attested","scanner_execution_attested",
        "production_ready","publication_authorized","status"
    } or m["schema"] != SCHEMA or m["name"] != NAME
        or m["status"] != "LOCAL_RC_UNATTESTED_NO_RELEASE"
        or not GIT_SHA.fullmatch(m["source_commit"])
        or m["build_profile"] != "release" or m["cargo_locked_offline"] is not True
        or m["tests_required"] is not True
        or any(m[k] is not False for k in (
            "signature_verified","source_publisher_attested","scanner_execution_attested",
            "production_ready","publication_authorized"))):
        raise InvalidCandidate("RELEASE_RECEIPT_SCHEMA_OR_AUTHORITY_INVALID")
    if not isinstance(m["version"],str) or not re.fullmatch(r"[0-9A-Za-z._+-]{1,48}", m["version"]):
        raise InvalidCandidate("RELEASE_VERSION_INVALID")
    if not isinstance(m["target"],str) or not re.fullmatch(r"[a-z0-9_-]{4,80}",m["target"]):
        raise InvalidCandidate("RELEASE_TARGET_INVALID")
    expected_archive = f"{NAME}-v{m['version']}-{m['target']}.tar.gz"
    expected_crate = f"{NAME}-{m['version']}.crate"
    portable = m["target"] == "x86_64-unknown-linux-musl"
    artifact_fields = {"archive","crate","binary_in_archive_sha256",
                       "third_party_notices_in_archive_sha256"}
    if portable:
        artifact_fields.add("rust_runtime_notices_in_archive_sha256")
    if (m["artifacts"].get("archive",{}).get("filename") != expected_archive or
        m["artifacts"].get("crate",{}).get("filename") != expected_crate or
        set(m["artifacts"]) != artifact_fields):
        raise InvalidCandidate("RELEASE_ARTIFACT_IDENTITY_INVALID")
    files = {expected_archive,expected_crate,"SHA256SUMS","manifest.json"}
    if {p.name for p in dest.iterdir()} != files:
        raise InvalidCandidate("RELEASE_CANDIDATE_UNEXPECTED_FILES")
    raw = {name:regular_file(dest / name) for name in files}
    sums = raw["SHA256SUMS"].decode("ascii").splitlines()
    actual = {}
    for line in sums:
        match = re.fullmatch(r"([a-f0-9]{64})  ([a-zA-Z0-9._+-]+)",line)
        if match is None or match[2] in actual:
            raise InvalidCandidate("INVALID_CHECKSUM_MANIFEST")
        actual[match[2]] = match[1]
    if set(actual) != files-{"SHA256SUMS"}:
        raise InvalidCandidate("CHECKSUM_MANIFEST_FILE_SCOPE_INVALID")
    if any(sha(raw[name]) != digest for name,digest in actual.items()):
        raise InvalidCandidate("CANDIDATE_FILE_CHECKSUM_MISMATCH")
    for kind,filename in (("archive",expected_archive),("crate",expected_crate)):
        value=m["artifacts"][kind]["sha256"]
        if not isinstance(value,str) or not HEX_SHA.fullmatch(value) or sha(raw[filename]) != value:
            raise InvalidCandidate("CANDIDATE_MANIFEST_ARTIFACT_HASH_MISMATCH")
    binary_sha=m["artifacts"]["binary_in_archive_sha256"]
    if not isinstance(binary_sha,str) or not HEX_SHA.fullmatch(binary_sha):
        raise InvalidCandidate("INVALID_BINARY_DIGEST")
    notices_sha=m["artifacts"]["third_party_notices_in_archive_sha256"]
    if not isinstance(notices_sha,str) or not HEX_SHA.fullmatch(notices_sha):
        raise InvalidCandidate("INVALID_LICENSE_NOTICES_DIGEST")
    runtime_notices_sha = m["artifacts"].get("rust_runtime_notices_in_archive_sha256")
    if portable and (not isinstance(runtime_notices_sha, str) or
                     not HEX_SHA.fullmatch(runtime_notices_sha)):
        raise InvalidCandidate("INVALID_RUST_RUNTIME_NOTICES_DIGEST")
    # Streaming archive parsing: check each member before decompression.
    # Never build a full untrusted member list from a tiny gzip bomb.
    seen=set()
    with tarfile.open(fileobj=io.BytesIO(raw[expected_archive]),mode="r|gz") as tar:
        expected={"bin/tredven-upstream","LICENSE","README.md","THIRD_PARTY_NOTICES.txt"}
        if portable:
            expected.add("RUST_RUNTIME_NOTICES.html")
        for item in tar:
            if item.name not in expected or item.name in seen or len(seen)>=len(expected):
                raise InvalidCandidate("UNEXPECTED_ARCHIVE_FILE_SCOPE")
            if (not item.isfile() or item.size<=0 or item.size>MAX_BYTES
                or item.mtime!=0 or item.uid!=0 or item.gid!=0 or item.name.startswith("/")):
                raise InvalidCandidate("UNSAFE_ARCHIVE_ENTRY")
            entry=tar.extractfile(item)
            if entry is None:
                raise InvalidCandidate("ARCHIVE_MEMBER_NOT_READABLE")
            contents=entry.read(item.size+1)
            if len(contents)!=item.size:
                raise InvalidCandidate("ARCHIVE_MEMBER_TRUNCATED")
            if item.name=="bin/tredven-upstream" and sha(contents)!=binary_sha:
                raise InvalidCandidate("CANDIDATE_BINARY_DIGEST_MISMATCH")
            if item.name=="THIRD_PARTY_NOTICES.txt" and sha(contents)!=notices_sha:
                raise InvalidCandidate("CANDIDATE_LICENSE_NOTICES_DIGEST_MISMATCH")
            if item.name=="RUST_RUNTIME_NOTICES.html" and sha(contents)!=runtime_notices_sha:
                raise InvalidCandidate("CANDIDATE_RUST_RUNTIME_NOTICES_DIGEST_MISMATCH")
            seen.add(item.name)
        if seen!=expected:
            raise InvalidCandidate("UNEXPECTED_ARCHIVE_FILE_SCOPE")
    return m


def run_cmd(args: list[str], cwd:Path, env:dict) -> str:
    print("+"," ".join(args),flush=True)
    result=subprocess.run(args,cwd=cwd,env=env,check=True,text=True,stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT,timeout=200)
    print(result.stdout[-2500:],flush=True)
    return result.stdout


def build_third_party_notices(repo: Path, env: dict) -> bytes:
    """Preserve license/notice text for EVERY locked registry crate; no legal inference.

    This is deliberately offline and fail-closed. Cargo, not a hand-maintained
    crate list, resolves the exact packages and source locations.
    """
    locked = tomllib.loads(regular_file(repo / "Cargo.lock").decode("utf-8"))
    lock_set = {(p["name"], p["version"], p["source"])
                for p in locked["package"] if p.get("source")}
    if len(lock_set) != sum(bool(p.get("source")) for p in locked["package"]):
        raise InvalidCandidate("DUPLICATE_LOCKED_CRATE_IDENTITY")
    if not lock_set or any(source != "registry+https://github.com/rust-lang/crates.io-index"
                           for _, _, source in lock_set):
        raise InvalidCandidate("UNQUALIFIED_LOCKED_CRATE_SOURCE")
    result = subprocess.run(
        ["cargo", "metadata", "--offline", "--locked", "--format-version", "1"],
        cwd=repo, env={**env, "CARGO_NET_OFFLINE": "true"}, capture_output=True,
        text=True, timeout=80, check=True)
    packages = [p for p in json.loads(result.stdout)["packages"] if p.get("source")]
    if (len(packages) != len(lock_set) or
        {(p["name"], p["version"], p["source"]) for p in packages} != lock_set):
        raise InvalidCandidate("CARGO_METADATA_LOCKED_CRATES_MISMATCH")

    registry_root = (Path(env.get("CARGO_HOME", Path.home() / ".cargo"))
                     / "registry" / "src").resolve()
    parts = [
        "TREDVEN UPSTREAM — THIRD-PARTY LICENSES AND NOTICES",
        "This file preserves the upstream license/notice files for every",
        "registry dependency in Cargo.lock (including build-only crates).",
        "License expressions are package-author metadata, not a legal opinion.",
        f"Original Cargo.lock SHA256: {sha(regular_file(repo / 'Cargo.lock'))}",
        f"Registry packages: {len(packages)}",
        "",
    ]
    for pkg in sorted(packages, key=lambda x: (x["name"], x["version"])):
        name, version = pkg["name"], pkg["version"]
        if (not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", name)
            or not re.fullmatch(r"[A-Za-z0-9._+-]{1,60}", version)
            or not isinstance(pkg.get("license"), str) or not pkg["license"]):
            raise InvalidCandidate("MISSING_OR_INVALID_UPSTREAM_LICENSE_METADATA")
        root = Path(pkg["manifest_path"]).parent
        if (root.is_symlink() or root.name != f"{name}-{version}"
            or not root.resolve().is_relative_to(registry_root)):
            raise InvalidCandidate("UNTRUSTED_UPSTREAM_LICENSE_PATH")
        filenames = {
            f.name for f in root.iterdir()
            if f.name.upper().startswith(
                ("LICENSE", "LICENCE", "NOTICE", "COPYING", "COPYRIGHT", "UNLICENSE"))
            and (f.is_file() or f.is_symlink())
        }
        explicit = pkg.get("license_file")
        if explicit:
            file_path = Path(explicit)
            if not file_path.is_absolute():
                file_path = root / file_path
            if file_path.parent.resolve() != root.resolve():
                raise InvalidCandidate("LICENSE_FILE_OUTSIDE_CRATE_ROOT")
            filenames.add(file_path.name)
        if not filenames:
            raise InvalidCandidate("UPSTREAM_LICENSE_TEXT_MISSING:" + name)
        parts.extend([
            "=" * 72,
            f"Package: {name} {version}",
            f"License (as declared): {pkg['license']}",
            f"Source: https://crates.io/crates/{name}/{version}",
            "",
        ])
        for filename in sorted(filenames):
            raw = regular_file(root / filename, 1024 * 1024)
            try:
                decoded = raw.decode("utf-8")
            except UnicodeError as error:
                raise InvalidCandidate("NON_UTF8_UPSTREAM_LICENSE_TEXT:" + name) from error
            parts.extend([
                f"----- BEGIN {filename} (original SHA256: {sha(raw)}) -----",
                decoded,
                f"----- END {filename} -----",
                "",
            ])
    data = "\n".join(parts).encode("utf-8")
    if len(data) > MAX_BYTES:
        raise InvalidCandidate("UPSTREAM_LICENSE_NOTICES_OUT_OF_BOUNDS")
    return data


def local_build(out_arg: str, portable_musl: bool = False) -> dict:
    repo = Path(__file__).resolve().parent.parent
    output_root=repo/"output"
    if output_root.is_symlink():
        raise InvalidCandidate("OUTPUT_DIRECTORY_IS_SYMLINK")
    output_root.mkdir(mode=0o700, exist_ok=True)
    if not output_root.is_dir():
        raise InvalidCandidate("NOT_AN_OUTPUT_DIRECTORY")
    requested=Path(out_arg).absolute()
    if requested.parent.resolve()!=output_root.resolve() or requested.name in ("",".",".."):
        raise InvalidCandidate("RC_OUTPUT_MUST_BE_DIRECT_CHILD_OF_REPO_OUTPUT")
    if requested.exists() or requested.is_symlink():
        raise InvalidCandidate("OUTPUT_EXISTS_NO_OVERWRITE")
    if os.environ.get("CARGO_BUILD_TARGET") or os.environ.get("RUSTFLAGS") or os.environ.get("CARGO_ENCODED_RUSTFLAGS"):
        raise InvalidCandidate("NON_DEFAULT_TARGET_OR_RUSTFLAGS_NOT_QUALIFIED")
    env={**os.environ, "CARGO_NET_OFFLINE":"true", "SOURCE_DATE_EPOCH":"0",
         "TZ":"UTC","LC_ALL":"C","CARGO_TERM_COLOR":"never"}
    commit=run_cmd(["git","rev-parse","HEAD"],repo,env).strip()
    if not GIT_SHA.fullmatch(commit):
        raise InvalidCandidate("INVALID_GIT_HEAD")
    if run_cmd(["git","status","--porcelain","--untracked-files=all"],repo,env).strip():
        raise InvalidCandidate("DIRTY_GIT_WORKTREE_NO_RELEASE")
    if not (repo/"Cargo.lock").exists():
        raise InvalidCandidate("NO_LOCKFILE")
    expected_version=tomllib.loads((repo/"rust-toolchain.toml").read_text())["toolchain"]["channel"]
    rustc=run_cmd(["rustc","--version"],repo,env).strip()
    cargo=run_cmd(["cargo","--version"],repo,env).strip()
    if not rustc.startswith(f"rustc {expected_version} "):
        raise InvalidCandidate("TOOLCHAIN_DOES_NOT_MATCH_PINNED_RUST_VERSION")
    target=next((line.split(":",1)[1].strip() for line in
        run_cmd(["rustc","-vV"],repo,env).splitlines() if line.startswith("host:")),None)
    if target is None or not re.fullmatch(r"[a-z0-9_-]{4,80}",target) or "linux" not in target:
        raise InvalidCandidate("LINUX_HOST_TARGET_NOT_QUALIFIED")
    host_target = target
    runtime_notices = None
    if portable_musl:
        if host_target != "x86_64-unknown-linux-gnu":
            raise InvalidCandidate("PORTABLE_MUSL_REQUIRES_QUALIFIED_X86_64_GNU_HOST")
        target = "x86_64-unknown-linux-musl"
        sysroot = Path(run_cmd(["rustc","--print","sysroot"],repo,env).strip())
        # Use the exact pinned compiler toolchain's own linker and target std.
        # Neither an arbitrary PATH linker nor an inherited RUSTFLAGS may
        # silently alter this local, unsigned candidate.
        lld = sysroot/"lib"/"rustlib"/host_target/"bin"/"rust-lld"
        target_std = sysroot/"lib"/"rustlib"/target/"lib"
        if not lld.is_file() or not target_std.is_dir():
            raise InvalidCandidate("PINNED_MUSL_TARGET_OR_RUST_LLD_NOT_INSTALLED")
        runtime_notices = regular_file(
            sysroot/"share"/"doc"/"rust"/"COPYRIGHT-library.html")
        if b"musl libc" not in runtime_notices:
            raise InvalidCandidate("MUSL_LICENSE_TEXT_NOT_IN_PINNED_RUST_STD_NOTICES")
        env["CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER"] = str(lld)
    version=tomllib.loads((repo/"Cargo.toml").read_text())["package"]["version"]
    notices=build_third_party_notices(repo,env)
    run_cmd(["cargo","fmt","--check"],repo,env)
    run_cmd(["cargo","clippy","--offline","--locked","--all-targets","--","-D","warnings"],repo,env)
    run_cmd(["cargo","test","--offline","--locked","--all-targets"],repo,env)
    build_args = ["cargo","build","--offline","--locked","--release"]
    if portable_musl:
        build_args.extend(["--target",target])
    run_cmd(build_args,repo,env)
    run_cmd(["cargo","package","--offline","--locked"],repo,env)
    target_root=Path(env.get("CARGO_TARGET_DIR",str(repo/"target")))
    if not target_root.is_absolute(): target_root=repo/target_root
    binary_path = target_root/target/"release"/NAME if portable_musl else target_root/"release"/NAME
    binary=regular_file(binary_path)
    if portable_musl:
        # The different GLIBC baseline cannot be the 'portable' artifact.
        # Prove the target actually produced a static, no-interpreter ELF.
        headers = run_cmd(["readelf","-l",str(binary_path)],repo,env)
        libraries = run_cmd(["readelf","-d",str(binary_path)],repo,env)
        if "INTERP" in headers or "(NEEDED)" in libraries:
            raise InvalidCandidate("PORTABLE_BINARY_MUST_BE_STATIC_NO_DYNAMIC_LIBS")
    crate=regular_file(target_root/"package"/f"{NAME}-{version}.crate")
    license_bytes=regular_file(repo/"LICENSE")
    readme=regular_file(repo/"README.md")
    temp_dir=output_root/f".{requested.name}.staging-{os.getpid()}"
    if temp_dir.exists() or temp_dir.is_symlink():
        raise InvalidCandidate("STAGING_OUTPUT_EXISTS")
    try:
        m=write_candidate(temp_dir,binary=binary,crate=crate,
            license_bytes=license_bytes,readme=readme,notices=notices,source_commit=commit,
            version=version,target=target,rustc=rustc,cargo=cargo,
            runtime_notices=runtime_notices)
        verified=verify_candidate(temp_dir)
        if verified!=m:raise InvalidCandidate("PRE_RELEASE_SELF_VERIFICATION_FAILED")
        temp_dir.rename(requested)
    except BaseException:
        # Do NOT delete a possibly-partially created output automatically.
        # The stage name is not a release; leave it for owner inspection.
        raise
    return verified


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest="action",required=True)
    b=sub.add_parser("build",help="Offline local RC; never publish or sign")
    b.add_argument("--out",required=True)
    b.add_argument("--portable-musl", action="store_true",
                   help="Build a static x86_64 Linux musl archive with pinned Rust runtime notices")
    v=sub.add_parser("verify",help="Check RC bytes, not publisher trust")
    v.add_argument("--dir",required=True)
    args=p.parse_args()
    try:
        receipt=(local_build(args.out, args.portable_musl)
                 if args.action=="build" else verify_candidate(Path(args.dir)))
        print(json.dumps({
            "schema":SCHEMA,"result":"LOCAL_RC_VERIFIED_UNATTESTED_NO_RELEASE",
            "source_commit":receipt["source_commit"],"version":receipt["version"],
            "target":receipt["target"],"signature_verified":False,
            "production_ready":False,"publication_authorized":False
        },sort_keys=True))
    except (InvalidCandidate,ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError,tarfile.TarError) as err:
        print("BLOCKED_LOCAL_RELEASE_CANDIDATE:"+str(err)[:180],file=sys.stderr)
        return 2
    return 0


if __name__=="__main__":
    raise SystemExit(main())
