#!/usr/bin/env python3
"""R39: independent public PR10 -> dual signed GitHub CI artifact proof.

Thin, read-only adapter to the existing pinned Rust/Sigstore verifier.
Never implements its own crypto, runs PR binaries, deploys, releases or merges.
Before an actual main-registered R39 workflow run, this MUST remain HOLD.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess

if __package__:
    from . import r39_pr_head_ci_contract as r39
else:
    import r39_pr_head_ci_contract as r39

SIGNED_VERIFIER_SHA256='82a235129d523a9da8f36f9e9aedf4427b5cfe36d0c14b23f98242d4b5460809'
QUALIFIED_GH_SHA256='fa7cff06d4db9eee98e00b10ac93beebfe1822109ac04a6cbbf9d806c21d0073'
RUN_PATH='.github/workflows/r39-manual-pr-head-ci.yml'
MAX_JSON=700_000
MAX_RUN_ID=999_999_999_999


def executable_digest(path:Path)->str:
    try:
        meta=path.lstat()
        if not path.is_file() or path.is_symlink() or not 1<=meta.st_size<=128*1024*1024:
            raise r39.EvidenceHold('UNBOUNDED_OR_SYMLINK_VERIFIER_EXECUTABLE')
        h=sha256();size=0
        with path.open('rb') as f:
            for chunk in iter(lambda:f.read(1024*1024),b''):
                size+=len(chunk)
                if size>128*1024*1024:
                    raise r39.EvidenceHold('VERIFIER_EXCEEDS_SIZE_LIMIT')
                h.update(chunk)
    except OSError as exc:
        raise r39.EvidenceHold('VERIFIER_UNAVAILABLE') from exc
    if size!=meta.st_size or not os.access(path,os.X_OK):
        raise r39.EvidenceHold('VERIFIER_SIZE_CHANGED_OR_NOT_EXECUTABLE')
    return h.hexdigest()


def check_tools(verifier:Path,gh:Path):
    if (executable_digest(verifier)!=SIGNED_VERIFIER_SHA256 or
            executable_digest(gh)!=QUALIFIED_GH_SHA256):
        raise r39.EvidenceHold('UNEXPECTED_RUST_OR_QUALIFIED_GH_BINARY_DIGEST')


def subprocess_json(cmd:list[str], *, env=None)->dict:
    try:
        result=subprocess.run(cmd,text=True,capture_output=True,timeout=22,env=env)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise r39.EvidenceHold('OFFICIAL_SOURCE_OR_RUST_VERIFIER_UNAVAILABLE') from exc
    if not 1<=len(result.stdout)<=MAX_JSON:
        raise r39.EvidenceHold('MISSING_OR_OVERSIZED_VERIFIER_JSON')
    try:response=json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise r39.EvidenceHold('INVALID_VERIFIER_OR_GITHUB_JSON') from exc
    # Never print stderr (it can include provider or authentication details).
    if result.returncode!=0:
        raise r39.EvidenceHold('OFFICIAL_PROVIDER_READ_OR_VERIFIER_NOT_SUCCESSFUL')
    if not isinstance(response,dict):
        raise r39.EvidenceHold('MISSING_STRUCTURED_ORIGINAL_SOURCE')
    return response


def original_gh(gh:Path,endpoint:str,run_id:int)->dict:
    allowed={f'repos/{r39.REPOSITORY}/pulls/{r39.PR_NUMBER}',
             f'repos/{r39.REPOSITORY}/actions/runs/{run_id}'}
    if endpoint not in allowed:
        raise r39.EvidenceHold('UNAPPROVED_GITHUB_ENDPOINT_OR_WRITE')
    return subprocess_json([str(gh),'api','-X','GET',endpoint])


def env_from_official_run(run:dict,run_id:int)->dict:
    if (not isinstance(run,dict) or run.get('id')!=run_id
            or run.get('event')!='workflow_dispatch'
            or run.get('head_branch')!='main'
            or run.get('path')!=RUN_PATH
            or run.get('status')!='completed' or run.get('conclusion')!='success'
            or (run.get('repository') or {}).get('full_name')!=r39.REPOSITORY
            or (run.get('repository') or {}).get('id')!=r39.REPOSITORY_ID
            or (run.get('actor') or {}).get('login')!='PeterxVarga'
            or (run.get('triggering_actor') or {}).get('login')!='PeterxVarga'
            or not isinstance(run.get('run_attempt'),int)):
        raise r39.EvidenceHold('R39_RUN_NOT_OWNER_MAIN_SUCCESSFUL_WORKFLOW')
    env={'GITHUB_ACTIONS':'true','GITHUB_EVENT_NAME':run['event'],
         'GITHUB_REPOSITORY':r39.REPOSITORY,
         'GITHUB_REPOSITORY_ID':str(r39.REPOSITORY_ID),
         'GITHUB_REF':'refs/heads/main','GITHUB_ACTOR':run['actor']['login'],
         'GITHUB_TRIGGERING_ACTOR':run['triggering_actor']['login'],
         'GITHUB_SHA':run.get('head_sha'),
         'GITHUB_RUN_ID':str(run_id),
         'GITHUB_RUN_ATTEMPT':str(run['run_attempt'])}
    r39.validate_owner_main_env(env)
    return env


def verify_native_report(result:dict,*,artifact:Path,sha:str,run:dict)->bool:
    uri=f'https://github.com/{r39.REPOSITORY}/actions/runs/{run["id"]}/attempts/{run["run_attempt"]}'
    return (result.get('schema')=='tredven.upstream.gh-artifact-attestation.v1'
            and result.get('verdict')=='VERIFIED'
            and result.get('reason')=='SIGNED_ARTIFACT_PROVENANCE_AND_EXACT_IDENTITY_VERIFIED'
            and result.get('artifact_filename')==artifact.name
            and result.get('artifact_sha256')==sha
            and result.get('repo')==r39.REPOSITORY
            and result.get('repository_id')==str(r39.REPOSITORY_ID)
            and result.get('signer_workflow')==r39.SIGNER_WORKFLOW
            and result.get('source_ref')=='refs/heads/main'
            and result.get('source_commit')==run['head_sha']
            and result.get('verified_workflow_run_uri')==uri
            and all(result.get(k) is True for k in (
                'signatures_cryptographically_verified_by_gh',
                'validated_certificate_source_identity','trusted_timestamp_observed'))
            and all(result.get(k) is False for k in (
                'scanner_execution_verified','production_ready','release_authorized',
                'action_authorized','performed_mutations')))


def verify_one(verifier:Path,gh:Path,artifact:Path,run:dict)->dict:
    env=os.environ.copy()
    env['PATH']=str(gh.parent)+os.pathsep+env.get('PATH','')
    cmd=[str(verifier),'verify-attestation','--artifact',str(artifact),
         '--repo',r39.REPOSITORY,'--repo-id',str(r39.REPOSITORY_ID),
         '--signer-workflow',r39.SIGNER_WORKFLOW,
         '--source-ref','refs/heads/main','--source-commit',run['head_sha'],
         '--online','--format','json']
    return subprocess_json(cmd,env=env)


def qualify(*,run_id:int,gh:Path,verifier:Path,archive:Path,receipt:Path)->dict:
    if not isinstance(run_id,int) or not 1<=run_id<=MAX_RUN_ID:
        raise r39.EvidenceHold('R39_RUN_ID_NOT_BOUNDED')
    check_tools(verifier,gh)
    pr=original_gh(gh,f'repos/{r39.REPOSITORY}/pulls/{r39.PR_NUMBER}',run_id)
    source=r39.validate_pr(pr)
    run=original_gh(gh,f'repos/{r39.REPOSITORY}/actions/runs/{run_id}',run_id)
    env=env_from_official_run(run,run_id)
    receipt_obj=r39.read_json(receipt,64_000)
    unsigned=r39.validate_receipt(receipt_obj,pr,archive,env)
    actual_archive_sha=unsigned['archive_sha256']
    actual_receipt_sha=sha256(r39.read_regular(receipt,64_000)).hexdigest()
    archive_verification=verify_one(verifier,gh,archive,run)
    receipt_verification=verify_one(verifier,gh,receipt,run)
    a=verify_native_report(archive_verification,artifact=archive,sha=actual_archive_sha,run=run)
    b=verify_native_report(receipt_verification,artifact=receipt,sha=actual_receipt_sha,run=run)
    decision=('SIGNED_PR_HEAD_BUILD_AND_RECEIPT_VERIFIED_NO_DEPLOYMENT_AUTHORITY'
              if a and b else 'HOLD_PR_HEAD_SIGNATURES_OR_WORKFLOW_SOURCE_NOT_BOTH_VERIFIED')
    return {'schema':'tredven.upstream.r39.independent-pr-head-signed-ci-verification.v1',
            'pr':{'number':r39.PR_NUMBER,'head_sha':source['pr_head'],'base_sha':source['pr_base']},
            'workflow':{'run_id':run_id,'attempt':run['run_attempt'],
                        'signer_commit':run['head_sha'],'source_ref':'refs/heads/main'},
            'subjects':{'archive':{'sha256':actual_archive_sha,'official_rust_sigstore_verified':a},
                        'receipt':{'sha256':actual_receipt_sha,'official_rust_sigstore_verified':b}},
            'decision':decision,'ci_source_and_artifact_provenance_verified':a and b,
            'actual_upgrade_compatibility_verified':False,
            'deployment_artifact_digest_verified':False,
            'owner_deployment_acceptance_verified':False,
            'production_ready':False,'release_authorized':False,
            'performed_mutations':False,
            'safety':['READ_ONLY','NO_SEND','NO_DEPLOY','NO_RELEASE','NO_MERGE']}


def main(argv=None)->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run-id',type=int,required=True)
    p.add_argument('--archive',type=Path,required=True)
    p.add_argument('--receipt',type=Path,required=True)
    p.add_argument('--rust-verifier',type=Path,required=True)
    p.add_argument('--qualified-gh',type=Path,required=True)
    p.add_argument('--output-dir',type=Path,required=True)
    args=p.parse_args(argv)
    if args.output_dir.exists() or args.output_dir.is_symlink():
        p.error('OUTPUT_EXISTS_NO_OVERWRITE')
    try:
        report=qualify(run_id=args.run_id,gh=args.qualified_gh,
                       verifier=args.rust_verifier,archive=args.archive,receipt=args.receipt)
    except (r39.EvidenceHold,KeyError,TypeError) as exc:
        p.error('HOLD_'+str(exc))
    args.output_dir.mkdir(mode=0o700,parents=True,exist_ok=False)
    (args.output_dir/'r39_verified_pr_head_chain.json').write_text(
        json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'decision':report['decision'],
                      'signed_both':report['ci_source_and_artifact_provenance_verified'],
                      'deployment':report['deployment_artifact_digest_verified']}))
    return 0


if __name__=='__main__':raise SystemExit(main())
