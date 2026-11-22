#!/usr/bin/env python3
"""Create an UNSIGNED, source-bound R11 CI run receipt.

This script does not sign anything. The separate, owner-approved manual
GitHub Actions workflow signs its exact output via actions/attest-build-provenance.
Caller-controlled environment alone is NEVER a proof of workflow execution.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re

SCHEMA="tredven.upstream.ci-osv-receipt.v1"
ARGS="scan source --lockfile Cargo.lock --format json --all-packages --no-resolve --verbosity error"
VERSION="2.7.1"
BINARY_SHA="fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8"
MAX=8*1024*1024

def sha(b:bytes)->str:
    return hashlib.sha256(b).hexdigest()

def read(path:Path)->bytes:
    meta=path.lstat()
    if not path.is_file() or path.is_symlink() or not 0<meta.st_size<=MAX:
        raise ValueError("NOT_BOUNDED_REGULAR_FILE")
    raw=path.read_bytes()
    if not raw or len(raw)>MAX:raise ValueError("FILE_SIZE_CHANGED")
    return raw

def need(var:str,regex:str)->str:
    value=os.environ.get(var,"")
    if re.fullmatch(regex,value) is None:raise ValueError("INVALID_GITHUB_CONTEXT_"+var)
    return value

def create_receipt(evidence:Path,scanned_repo:str)->dict:
    if need("GITHUB_ACTIONS","true")!="true" or need("GITHUB_EVENT_NAME","workflow_dispatch")!="workflow_dispatch":
        raise ValueError("NOT_EXPLICIT_MANUAL_CI_CONTEXT")
    repo=need("GITHUB_REPOSITORY",r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
    if repo!="PeterxVarga/tredven-upstream":raise ValueError("UNEXPECTED_SIGNING_REPOSITORY")
    repo_id=need("GITHUB_REPOSITORY_ID",r"[1-9][0-9]{0,19}")
    if repo_id!="1467524521":raise ValueError("UNEXPECTED_SIGNING_REPOSITORY_ID")
    ref=need("GITHUB_REF",r"refs/heads/[A-Za-z0-9_./-]+")
    if ".." in ref:raise ValueError("UNSAFE_SIGNER_SOURCE_REF")
    if ref!="refs/heads/main":raise ValueError("UNEXPECTED_SIGNER_SOURCE_REF")
    commit=need("GITHUB_SHA",r"[a-fA-F0-9]{40}")
    run_id=need("GITHUB_RUN_ID",r"[1-9][0-9]{0,23}")
    attempt=int(need("GITHUB_RUN_ATTEMPT",r"[1-9][0-9]{0,3}"))
    if attempt>1000:raise ValueError("RUN_ATTEMPT_OUT_OF_BOUNDS")
    if scanned_repo!="attested-delivery/rust-template":
        raise ValueError("UNEXPECTED_PUBLIC_SCANNED_REPOSITORY")
    report=json.loads(read(evidence/"review.json"))
    if report.get("schema")!="tredven.upstream.upgrade-review.v1" or \
       report.get("scan_mode")!="local-osv-lockfile" or \
       report.get("scanner_binary_sha256")!=BINARY_SHA or \
       report.get("decision") not in ("BLOCKED","REVIEW") or \
       report.get("delta",{}).get("comparable_scan_scope") is not True or \
       report.get("source_remote_publisher_attested") is not False or \
       report.get("release_authorized") is not False:
        raise ValueError("UNQUALIFIED_R10_REVIEW_RESULT")
    source=report["source"]
    if source["baseline_tag"]!="v0.1.0" or \
       source["baseline_commit"]!="2b97f20f71e2b6d9c3f23ea7e968b7dd26d97e6a" or \
       source["candidate_tag"]!="r11-local-main-snapshot" or \
       source["candidate_commit"]!="44d052afce639390846b9369be3d4ea684f4e7c4":
        raise ValueError("SCANNED_SOURCE_TAG_AND_COMMIT_MISMATCH")
    payload={
        "schema":SCHEMA,
        "scanned_repository":scanned_repo,
        "workflow":{
            "repository":repo,"repository_id":repo_id,
            "source_ref":ref,"source_commit":commit,
            "run_id":run_id,"run_attempt":attempt,
        },
        "scanner":{
            "tool":"osv-scanner","version":VERSION,
            "binary_sha256":BINARY_SHA,"args":ARGS,
        },
        "local_scanner_processes_observed":True,
        "scan_generator":"tredven-upstream review-upgrade local-osv-lockfile",
    }
    for side in ("baseline","candidate"):
        obj=report[side]
        lock=read(evidence/f"{side}.Cargo.lock")
        scan=read(evidence/f"{side}.scanner.json")
        if obj.get("input_lockfile_sha256")!=sha(lock) or obj.get("report_sha256")!=sha(scan):
            raise ValueError("SCANNED_ARTIFACT_BYTES_MISMATCH")
        exit_code=obj.get("local_scanner_process_exit")
        if obj.get("local_execution_observed") is not True or exit_code not in (0,1):
            raise ValueError("SCANNER_EXIT_STATUS_NOT_OBSERVED")
        native=json.loads(scan)
        packages=native.get("results",[])
        if not packages or not any(r.get("packages") for r in packages):
            raise ValueError("SCANNER_REPORT_NO_ENUMERATED_PACKAGES")
        count=sum(len(p.get("vulnerabilities",[])) for r in packages for p in r.get("packages",[]))
        if (exit_code==1) != (count>0):
            raise ValueError("SCANNER_EXIT_STATUS_CONTRADICTS_FINDINGS")
        payload[side]={
            "tag":source[f"{side}_tag"],
            "commit":source[f"{side}_commit"],
            "lockfile_sha256":sha(lock),
            "report_sha256":sha(scan),
            "exit_code":obj["local_scanner_process_exit"]
        }
    return payload

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--evidence-dir",required=True,type=Path)
    p.add_argument("--scanned-repo",default="attested-delivery/rust-template")
    p.add_argument("--out",required=True,type=Path)
    args=p.parse_args()
    if args.out.exists() or args.out.is_symlink():raise ValueError("RECEIPT_OUTPUT_EXISTS")
    result=create_receipt(args.evidence_dir,args.scanned_repo)
    # Schema/signing controls are enforced by the actual GH attestation,
    # NOT by self-declared GITHUB_* values or a local SHA256 checksum.
    with args.out.open("xb") as fd:
        fd.write((json.dumps(result,sort_keys=True,indent=2)+"\n").encode())
    args.out.chmod(0o600)
    print("UNSIGNED_CI_RECEIPT_CREATED_FOR_SEPARATE_GITHUB_ATTESTATION")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
