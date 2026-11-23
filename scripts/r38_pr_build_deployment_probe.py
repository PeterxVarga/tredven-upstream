#!/usr/bin/env python3
"""R38: bounded read-only join of a real GitHub PR, signed run and deploy evidence.

No new signer, no deployment, no check mutation. Uses an EXACT SHA-pinned
existing Tredven Rust verifier and GH CLI qualified by that verifier.
This is a single, useful chain falsifier, NOT a deployment authorizer.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import urlsplit

SCHEMA = "tredven.upstream.r38.pr-run-artifact-deployment-chain.v1"
REPO = "PeterxVarga/tredven-upstream"
REPO_ID = 1467524521
WORKFLOW = "r20-manual-alpha-provenance.yml"
WORKFLOW_PATH = ".github/workflows/" + WORKFLOW
SIGNER = REPO + "/" + WORKFLOW_PATH
# Real R20 GitHub-hosted, statically linked, owner-verified alpha binary.
# Do NOT quietly trust a different executable returning 'VERIFIED'.
EXISTING_RUST_VERIFIER_SHA256 = "82a235129d523a9da8f36f9e9aedf4427b5cfe36d0c14b23f98242d4b5460809"
EXISTING_QUALIFIED_GH_SHA256 = "fa7cff06d4db9eee98e00b10ac93beebfe1822109ac04a6cbbf9d806c21d0073"
MAX_ARTIFACT = 20 * 1024 * 1024
MAX_JSON = 700_000
SHA40 = re.compile(r"[a-f0-9]{40}\Z")
SHA64 = re.compile(r"[a-f0-9]{64}\Z")


class SourceNotVerified(ValueError):
    """Untrusted/missing original evidence, not a successful negative result."""


def bounded_file(path: Path, limit: int) -> bytes:
    try:
        st = path.lstat()
        if not path.is_file() or path.is_symlink() or not 1 <= st.st_size <= limit:
            raise SourceNotVerified("UNBOUNDED_OR_SYMLINK_INPUT")
        raw = path.read_bytes()
    except OSError as exc:
        raise SourceNotVerified("REQUIRED_ORIGINAL_FILE_UNAVAILABLE") from exc
    if not 1 <= len(raw) <= limit:
        raise SourceNotVerified("ORIGINAL_FILE_SIZE_CHANGED")
    return raw


def executable_sha256(path: Path) -> str:
    """Stream larger qualified GH binaries; never load 40+ MiB into RAM."""
    try:
        st=path.lstat()
        if not path.is_file() or path.is_symlink() or not 1<=st.st_size<=128*1024*1024:
            raise SourceNotVerified("UNBOUNDED_OR_SYMLINK_EXECUTABLE")
        digest=sha256()
        count=0
        with path.open('rb') as handle:
            for chunk in iter(lambda:handle.read(1024*1024),b''):
                count+=len(chunk)
                if count>128*1024*1024:
                    raise SourceNotVerified("EXE_BYTE_BUDGET_EXCEEDED")
                digest.update(chunk)
    except OSError as exc:
        raise SourceNotVerified("PINNED_EXECUTABLE_UNREADABLE") from exc
    if count!=st.st_size:
        raise SourceNotVerified("EXECUTABLE_SIZE_CHANGED_DURING_READ")
    return digest.hexdigest()


def pinned_executables(verifier: Path, gh: Path) -> None:
    expected = ((verifier, EXISTING_RUST_VERIFIER_SHA256),
                (gh, EXISTING_QUALIFIED_GH_SHA256))
    for path, digest in expected:
        if executable_sha256(path) != digest:
            raise SourceNotVerified("PINNED_TRUSTED_EXECUTABLE_SHA256_MISMATCH")
        if not os.access(path, os.X_OK):
            raise SourceNotVerified("VERIFIER_EXECUTABLE_NOT_ALLOWED")


def command_json(argv: list[str], *, env: dict[str, str] | None = None) -> dict | list:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=20,
                                check=False, env=env)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SourceNotVerified("READ_ONLY_OR_VERIFIER_EXECUTION_FAILED") from exc
    # Never print stderr (may include auth/provider state). Fail closed.
    if len(result.stdout) > MAX_JSON or not result.stdout:
        raise SourceNotVerified("EMPTY_OR_OVERSIZED_OFFICIAL_SOURCE_RESPONSE")
    try:
        obj = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SourceNotVerified("INVALID_OFFICIAL_JSON_RESPONSE") from exc
    if result.returncode != 0:
        # A signed verifier returns a structured BLOCKED result with an error
        # exit code. Keep it as evidence; don't turn it into a PASS.
        if not (isinstance(obj, dict) and obj.get("verdict") == "BLOCKED"):
            raise SourceNotVerified("OFFICIAL_SOURCE_READ_OR_SIGNATURE_FAILED")
    return obj


def gh_get(gh: Path, endpoint: str, *, pr: int, run_id: int, pr_sha: str | None = None):
    prefix = f"repos/{REPO}/"
    allowed = {
        f"{prefix}pulls/{pr}",
        f"{prefix}actions/runs/{run_id}",
        f"{prefix}actions/runs/{run_id}/artifacts?per_page=100",
    }
    if pr_sha is not None and SHA40.fullmatch(pr_sha):
        allowed.add(f"{prefix}commits/{pr_sha}/check-runs?per_page=100")
        allowed.add(f"{prefix}deployments?sha={pr_sha}&per_page=100")
    if endpoint not in allowed:
        raise SourceNotVerified("UNPINNED_OR_MUTATING_GITHUB_API_ENDPOINT")
    result = command_json([str(gh), "api", "-X", "GET", endpoint])
    return result


def native_verify(verifier: Path, gh: Path, artifact: Path, run: dict):
    if (not isinstance(run, dict) or run.get("head_branch") != "main"
            or run.get("path") != WORKFLOW_PATH
            or not SHA40.fullmatch(str(run.get("head_sha", "")))):
        raise SourceNotVerified("INVALID_SIGNER_RUN_SOURCE_IDENTITY")
    env = os.environ.copy()
    env["PATH"] = str(gh.parent) + os.pathsep + env.get("PATH", "")
    cmd = [str(verifier), "verify-attestation", "--artifact", str(artifact),
           "--repo", REPO, "--repo-id", str(REPO_ID), "--signer-workflow", SIGNER,
           "--source-ref", "refs/heads/main", "--source-commit", run["head_sha"],
           "--online", "--format", "json"]
    return command_json(cmd, env=env)


def _sha(value) -> bool:
    return isinstance(value, str) and SHA40.fullmatch(value) is not None


def assess(*, pr: dict, run: dict, artifacts: dict, checks: dict,
           deployments: list, native: dict, manifest: dict,
           archive_name: str, archive_sha: str, pr_number: int, run_id: int) -> dict:
    """Pure correlation; caller MUST obtain API data and native proof securely."""
    if not isinstance(pr, dict) or not isinstance(run, dict) or not isinstance(artifacts, dict):
        raise SourceNotVerified("SOURCE_STRUCTURES_UNAVAILABLE")
    head = pr.get("head") or {}
    base = pr.get("base") or {}
    if (pr.get("number") != pr_number or (head.get("repo") or {}).get("full_name") != REPO
            or pr.get("state") != "open" or pr.get("draft") is not True
            or not _sha(head.get("sha")) or not _sha(base.get("sha"))
            or not isinstance(pr.get("html_url"), str)
            or pr["html_url"] != f"https://github.com/{REPO}/pull/{pr_number}"):
        raise SourceNotVerified("UNEXPECTED_GITHUB_PR_SOURCE_OR_STATE")
    source_sha = head["sha"]
    run_sha = run.get("head_sha")
    if (run.get("id") != run_id or run.get("status") != "completed"
            or run.get("conclusion") != "success" or run.get("path") != WORKFLOW_PATH
            or run.get("event") != "workflow_dispatch" or run.get("head_branch") != "main"
            or (run.get("repository") or {}).get("full_name") != REPO
            or (run.get("repository") or {}).get("id") != REPO_ID
            or not _sha(run_sha) or not isinstance(run.get("run_attempt"), int)
            or not 1 <= run["run_attempt"] <= 100):
        raise SourceNotVerified("UNEXPECTED_SIGNED_RUN_WORKFLOW_IDENTITY")
    archive_subject = manifest.get("artifacts", {}).get("archive") or {}
    if (manifest.get("schema") != "tredven.upstream.local-release-candidate.v2"
            or manifest.get("source_commit") != run_sha
            or archive_subject.get("filename") != archive_name
            or archive_subject.get("sha256") != archive_sha
            or any(manifest.get(k) is not False for k in
                   ("production_ready", "publication_authorized", "signature_verified"))):
        raise SourceNotVerified("ORIGINAL_LOCAL_MANIFEST_CONTRADICTS_BYTES_OR_RUN")
    if not SHA64.fullmatch(archive_sha):
        raise SourceNotVerified("MALFORMED_SIGNED_ARTIFACT_SHA256")
    expected_uri=f"https://github.com/{REPO}/actions/runs/{run_id}/attempts/{run['run_attempt']}"
    verified = (isinstance(native, dict)
                and native.get("schema") == "tredven.upstream.gh-artifact-attestation.v1"
                and native.get("verdict") == "VERIFIED"
                and native.get("artifact_filename") == archive_name
                and native.get("artifact_sha256") == archive_sha
                and native.get("repo") == REPO
                and native.get("repository_id") == str(REPO_ID)
                and native.get("source_commit") == run_sha
                and native.get("source_ref") == "refs/heads/main"
                and native.get("signer_workflow") == SIGNER
                and native.get("verified_workflow_run_uri") == expected_uri
                and all(native.get(k) is True for k in
                        ("signatures_cryptographically_verified_by_gh",
                         "validated_certificate_source_identity",
                         "trusted_timestamp_observed"))
                and all(native.get(k) is False for k in
                        ("production_ready", "release_authorized", "action_authorized",
                         "performed_mutations")))
    if not isinstance(artifacts.get("artifacts"), list) or not isinstance(artifacts.get("total_count"), int):
        raise SourceNotVerified("ARTIFACT_STORAGE_METADATA_UNAVAILABLE")
    artifact_names = {"r20-alpha-candidate-bytes", "r20-alpha-attestation-bundle"}
    matching_artifacts = [a for a in artifacts["artifacts"] if a.get("name") in artifact_names]
    metadata_available = (
        artifacts["total_count"] <= 100 and
        len(matching_artifacts) == 2 and
        {a.get("name") for a in matching_artifacts} == artifact_names and
        all(a.get("expired") is False and
            (a.get("workflow_run") or {}).get("head_sha") == run_sha and
            (a.get("workflow_run") or {}).get("id") == run_id and
            re.fullmatch(r"sha256:[a-f0-9]{64}",str(a.get("digest")))
            for a in matching_artifacts)
    )
    # Stored Actions ZIP digest is NOT equal to the verified inner tarball's SHA.
    if not isinstance(checks, dict) or not isinstance(checks.get("check_runs"), list) or not isinstance(checks.get("total_count"), int):
        raise SourceNotVerified("EXACT_PR_GITHUB_CHECKS_UNAVAILABLE")
    if not isinstance(deployments, list):
        raise SourceNotVerified("PR_GITHUB_DEPLOYMENTS_UNAVAILABLE")
    signed_run_url=expected_uri.rsplit("/attempts/",1)[0]
    def check_details_matches(url) -> bool:
        if not isinstance(url,str):
            return False
        try:
            parsed=urlsplit(url)
            expected=urlsplit(signed_run_url)
        except ValueError:
            return False
        return (parsed.scheme=="https" and parsed.netloc=="github.com"
                and (parsed.path==expected.path or parsed.path.startswith(expected.path+"/")))
    checked_run = any(
        x.get("head_sha") == source_sha and x.get("status") == "completed"
        and x.get("conclusion") == "success" and check_details_matches(x.get("details_url"))
        for x in checks["check_runs"]
    ) if checks["total_count"] <= 100 else False
    # GitHub deployment records, even if present, don't prove the deployed
    # bytes match the signed artifact. Require an independently trusted, exact
    # digest and authorized acceptance in a FUTURE separately scoped gate.
    have_deploy_record = bool(deployments)
    deployment_list_may_be_paginated = len(deployments) == 100
    blockers=[]
    if not verified:
        blockers.append("EXISTING_RUST_ATTESTATION_NOT_VERIFIED_FOR_EXACT_RUN")
    if not metadata_available:
        blockers.append("GITHUB_RUN_ARTIFACT_STORAGE_PROVENANCE_INCOMPLETE")
    if source_sha != run_sha:
        blockers.append("PR_HEAD_AND_SIGNED_RUN_SOURCE_COMMIT_DIFFER")
    if not checked_run:
        blockers.append("NO_EXACT_PR_BOUND_SUCCESSFUL_GITHUB_CHECK_FOR_SIGNED_RUN")
    blockers.extend(("DEPLOYED_ARTIFACT_DIGEST_NOT_VERIFIED",
                     "AUTHORIZED_DEPLOYMENT_ACCEPTANCE_NOT_VERIFIED"))
    return {
        "schema":SCHEMA,
        "mode":"PUBLIC_GITHUB_READONLY_EXISTING_RUST_SIGSTORE_VERIFIER",
        "pr":{"url":pr["html_url"],"number":pr_number,"head_sha":source_sha,
              "base_sha":base["sha"],"draft":True},
        "run":{"url":f"https://github.com/{REPO}/actions/runs/{run_id}",
               "run_id":run_id,"attempt":run["run_attempt"],"head_sha":run_sha,
               "event":run["event"],"workflow":run["path"],"conclusion":"success"},
        "signed_artifact":{"filename":archive_name,"sha256":archive_sha,
                           "cryptographic_provenance_verified_by_existing_rust":bool(verified),
                           "verified_exact_source_run_uri":expected_uri if verified else None,
                           "github_actions_storage_zip_metadata_available":metadata_available,
                           "storage_zip_digest_is_not_inner_tar_digest":True},
        "stages":{
            "pr_identity":"ORIGINAL_GITHUB_PR_CONFIRMED",
            "build_ci":"SUCCESSFUL_MAIN_WORKFLOW_NOT_BOUND_TO_PR" if source_sha != run_sha else (
                "EXACT_PR_CHECK_MATCHED" if checked_run else "EXACT_PR_CHECK_NOT_EVIDENCED"),
            "artifact":"SIGNED_MAIN_RUN_ARTIFACT_VERIFIED_NOT_PR_SOURCE" if verified and source_sha!=run_sha else (
                "SIGNED_ARTIFACT_SOURCE_MATCHED" if verified else "ATTESTATION_UNKNOWN_OR_BLOCKED"),
            "deployment":("GITHUB_DEPLOYMENT_RECORD_EXISTS_DIGEST_NOT_VERIFIED" if have_deploy_record
                          else "NO_MATCHING_GITHUB_DEPLOYMENT_EXTERNAL_UNKNOWN"),
            "acceptance":"NO_CRYPTOGRAPHICALLY_TRUSTED_OWNER_ACCEPTANCE",
        },
        "source_binding":{"pr_head_equals_signed_run_source":source_sha==run_sha,
                          "pr_has_matching_run_check":checked_run,
                          "pr_check_runs_reported":checks["total_count"],
                          "github_deployments_for_pr_head_reported":len(deployments),
                          "github_deployments_list_complete":not deployment_list_may_be_paginated},
        "deployment_digest_verified":False,
        "owner_acceptance_verified":False,
        "production_ready":False,
        "commercial_winner":None,
        "decision":"HOLD_PR_TO_SIGNED_BUILD_SOURCE_MISMATCH" if source_sha != run_sha else (
            "HOLD_SIGNED_BUILD_OR_PR_CHECK_UNPROVEN" if not verified or not checked_run else
            "HOLD_DEPLOYMENT_DIGEST_AND_OWNER_ACCEPTANCE_UNPROVEN"),
        "blockers":blockers,
        "next_decisive_test":"Separately authorized PR-head-bound hosted CI with signed exact artifact, followed by read-only deployed digest and owner acceptance provenance; do not deploy or dispatch in this audit.",
        "safety":["NO_SEND","NO_PUSH_BY_PROBE","NO_MERGE","NO_DEPLOY","NO_WORKFLOW_DISPATCH",
                  "NO_CUSTOMER_DATA","NO_NEW_PROVIDER","NO_PAID_API"],
        "performed_external_mutations":False,
    }


def probe(*, gh: Path, verifier: Path, pr_number: int, run_id: int,
          artifact: Path, manifest_file: Path) -> dict:
    if not 1 <= pr_number <= 1000 or not 1 <= run_id <= 999_999_999_999:
        raise SourceNotVerified("UNBOUNDED_GITHUB_PR_OR_RUN_ID")
    pinned_executables(verifier,gh)
    archive_raw=bounded_file(artifact,MAX_ARTIFACT)
    manifest_raw=bounded_file(manifest_file,64_000)
    try:
        manifest=json.loads(manifest_raw)
    except json.JSONDecodeError as exc:
        raise SourceNotVerified("UNPARSEABLE_RELEASE_MANIFEST") from exc
    if not isinstance(manifest,dict):
        raise SourceNotVerified("INVALID_RELEASE_MANIFEST")
    prefix=f"repos/{REPO}/"
    pr=gh_get(gh,f"{prefix}pulls/{pr_number}",pr=pr_number,run_id=run_id)
    run=gh_get(gh,f"{prefix}actions/runs/{run_id}",pr=pr_number,run_id=run_id)
    if not isinstance(pr,dict) or not isinstance(run,dict):
        raise SourceNotVerified("INVALID_ORIGINAL_PR_OR_RUN_DATA")
    sha=(pr.get('head') or {}).get('sha')
    if not _sha(sha):
        raise SourceNotVerified("UNRESOLVED_PR_HEAD_COMMIT")
    storage=gh_get(gh,f"{prefix}actions/runs/{run_id}/artifacts?per_page=100",
                   pr=pr_number,run_id=run_id)
    checks=gh_get(gh,f"{prefix}commits/{sha}/check-runs?per_page=100",
                  pr=pr_number,run_id=run_id,pr_sha=sha)
    deployed=gh_get(gh,f"{prefix}deployments?sha={sha}&per_page=100",
                    pr=pr_number,run_id=run_id,pr_sha=sha)
    native=native_verify(verifier,gh,artifact,run)
    return assess(pr=pr,run=run,artifacts=storage,checks=checks,
                  deployments=deployed,native=native,manifest=manifest,
                  archive_name=artifact.name,archive_sha=sha256(archive_raw).hexdigest(),
                  pr_number=pr_number,run_id=run_id)


def markdown(report: dict) -> str:
    s=report["stages"]
    return "\n".join([
        "# R38 — real GitHub PR → signed build → deployment evidence", "",
        f"**Decision:** `{report['decision']}` (read-only, no deployment)", "",
        f"**PR:** {report['pr']['url']} at `{report['pr']['head_sha']}`",
        f"**Signed workflow:** {report['run']['url']} at `{report['run']['head_sha']}`", "",
        "| Stage | Original-source verdict |", "| --- | --- |",
        *(f"| {name} | {status} |" for name,status in s.items()), "",
        "**Signed artifact (SHA-256):** `"+report['signed_artifact']['sha256']+"`",
        "**Proof limits:** `manifest.json` is pre-signing release metadata; GitHub Actions ZIP digests are not tarball digests; cryptographic provenance is not deployment or customer approval.", "",
        "**Next falsifier:** "+report['next_decisive_test'], "",
        "This probe never contacts source authors, dispatches CI, opens a PR, pushes code or deploys a product.", "",
    ])


def main(argv=None) -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pr',type=int,required=True)
    p.add_argument('--run-id',type=int,required=True)
    p.add_argument('--artifact',type=Path,required=True)
    p.add_argument('--manifest',type=Path,required=True)
    p.add_argument('--rust-verifier',type=Path,required=True)
    p.add_argument('--qualified-gh',type=Path,required=True)
    p.add_argument('--output-dir',type=Path,required=True)
    a=p.parse_args(argv)
    if a.output_dir.exists() or a.output_dir.is_symlink():
        p.error('OUTPUT_EXISTS_NO_OVERWRITE')
    try:
        report=probe(gh=a.qualified_gh,verifier=a.rust_verifier,pr_number=a.pr,
                     run_id=a.run_id,artifact=a.artifact,manifest_file=a.manifest)
    except SourceNotVerified as exc:
        p.error(str(exc))
    a.output_dir.mkdir(parents=True,mode=0o700,exist_ok=False)
    (a.output_dir/'r38_evidence_chain.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    (a.output_dir/'r38_evidence_chain.md').write_text(markdown(report)+'\n')
    print(json.dumps({'output_directory':str(a.output_dir),'decision':report['decision'],
                      'cryptographic_provenance':report['signed_artifact']['cryptographic_provenance_verified_by_existing_rust'],
                      'source_bound':report['source_binding']['pr_head_equals_signed_run_source'],
                      'deployed_artifact_digest_verified':report['deployment_digest_verified']}))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
