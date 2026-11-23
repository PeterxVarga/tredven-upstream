#!/usr/bin/env python3
"""R39 fixed, owner-gated PR10 build-evidence contract (NOT a signer).

The reviewed default-branch workflow alone may produce GitHub/Sigstore
attestations. This parser verifies original PR metadata, exact source SHA,
archive bytes, and unsigned receipt bindings. It never grants deployment.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import tarfile

SCHEMA='tredven.upstream.r39.pr10-source-build-receipt.v1'
REPOSITORY='PeterxVarga/tredven-upstream'
REPOSITORY_ID=1467524521
PR_NUMBER=10
PR_HEAD='1c8a15ad84858bead99b88e655915975ceefb2e9'
PR_BASE='44d6eef16de40e33474e578c0ffcd7a2e1b4c698'
PR_BRANCH='feat/r30-github-zero-to-value-20261122'
BASE_BRANCH='feat/r29-real-app-ci-provenance-gate-20261122'
SIGNER_WORKFLOW=REPOSITORY+'/.github/workflows/r39-manual-pr-head-ci.yml'
ARCHIVE_NAME='r39-pr10-rust-ci.tar.gz'
RECEIPT_NAME='r39-pr10-build.receipt.json'
MAX_ARCHIVE=22*1024*1024
SHA40=re.compile(r'[0-9a-f]{40}\Z')
SHA64=re.compile(r'[0-9a-f]{64}\Z')


class EvidenceHold(ValueError):
    pass


def read_regular(path:Path,maximum:int)->bytes:
    try:
        st=path.lstat()
        if not path.is_file() or path.is_symlink() or not 1<=st.st_size<=maximum:
            raise EvidenceHold('SOURCE_NOT_BOUNDED_REGULAR_FILE')
        raw=path.read_bytes()
    except OSError as exc:
        raise EvidenceHold('ORIGINAL_SOURCE_UNAVAILABLE') from exc
    if not 1<=len(raw)<=maximum:
        raise EvidenceHold('SOURCE_CHANGED_OR_OVERSIZED')
    return raw


def read_json(path:Path,maximum:int=100_000)->dict:
    try:
        obj=json.loads(read_regular(path,maximum))
    except (ValueError,UnicodeDecodeError) as exc:
        raise EvidenceHold('MALFORMED_EVIDENCE_JSON') from exc
    if not isinstance(obj,dict):
        raise EvidenceHold('NOT_AN_EVIDENCE_OBJECT')
    return obj


def validate_pr(obj:dict)->dict:
    if not isinstance(obj,dict):
        raise EvidenceHold('INVALID_PR_METADATA')
    h=obj.get('head') or {}
    b=obj.get('base') or {}
    if (obj.get('number')!=PR_NUMBER or obj.get('state')!='open' or obj.get('draft') is not True
        or obj.get('html_url')!=f'https://github.com/{REPOSITORY}/pull/{PR_NUMBER}'
        or (obj.get('base') or {}).get('sha')!=PR_BASE or b.get('ref')!=BASE_BRANCH
        or h.get('sha')!=PR_HEAD or h.get('ref')!=PR_BRANCH
        or (h.get('repo') or {}).get('full_name')!=REPOSITORY
        or (h.get('repo') or {}).get('id')!=REPOSITORY_ID):
        raise EvidenceHold('PR_IDENTITY_OR_COMMIT_CHANGED_REQUIRES_OWNER_REVIEW')
    return {'repository':REPOSITORY,'repository_id':REPOSITORY_ID,
            'pr_number':PR_NUMBER,'pr_head':PR_HEAD,'pr_base':PR_BASE,
            'pr_url':obj['html_url'],'pr_branch':PR_BRANCH}


def validate_owner_main_env(env:dict)->dict:
    expected={'GITHUB_ACTIONS':'true','GITHUB_EVENT_NAME':'workflow_dispatch',
              'GITHUB_REPOSITORY':REPOSITORY,'GITHUB_REPOSITORY_ID':str(REPOSITORY_ID),
              'GITHUB_REF':'refs/heads/main','GITHUB_ACTOR':'PeterxVarga',
              'GITHUB_TRIGGERING_ACTOR':'PeterxVarga'}
    if any(env.get(k)!=v for k,v in expected.items()):
        raise EvidenceHold('OWNER_DEFAULT_BRANCH_WORKFLOW_POLICY_NOT_MET')
    source=env.get('GITHUB_SHA')
    run_id=env.get('GITHUB_RUN_ID')
    attempt=env.get('GITHUB_RUN_ATTEMPT')
    if not isinstance(source,str) or not SHA40.fullmatch(source):
        raise EvidenceHold('INVALID_PROTECTED_WORKFLOW_COMMIT')
    if not isinstance(run_id,str) or not re.fullmatch(r'[1-9][0-9]{0,16}',run_id):
        raise EvidenceHold('INVALID_SIGNING_RUN_ID')
    if not isinstance(attempt,str) or not attempt.isdecimal() or not 1<=int(attempt)<=100:
        raise EvidenceHold('INVALID_SIGNING_RUN_ATTEMPT')
    return {'source_ref':'refs/heads/main','source_commit':source,
            'run_id':run_id,'run_attempt':int(attempt)}


def archive_evidence(archive:Path)->dict:
    raw=read_regular(archive,MAX_ARCHIVE)
    try:
        with tarfile.open(fileobj=__import__('io').BytesIO(raw),mode='r:gz') as tf:
            members=tf.getmembers()
            if len(members)!=1 or members[0].name!='tredven-upstream' or not members[0].isfile() or not 1<=members[0].size<=20*1024*1024:
                raise EvidenceHold('ARCHIVE_CONTAINS_UNEXPECTED_FILES_OR_LINKS')
            member=tf.extractfile(members[0])
            if member is None:
                raise EvidenceHold('ARCHIVE_BINARY_UNREADABLE')
            binary=member.read(20*1024*1024+1)
            if len(binary)!=members[0].size:
                raise EvidenceHold('ARCHIVE_BINARY_SIZE_MISMATCH')
    except (tarfile.TarError,OSError,EOFError) as exc:
        raise EvidenceHold('ARCHIVE_NOT_VALID_GZIP_TAR') from exc
    return {'archive_filename':archive.name,'archive_sha256':sha256(raw).hexdigest(),
            'binary_sha256':sha256(binary).hexdigest(),'archive_bytes':len(raw)}


def make_receipt(pr:dict,archive:Path,binary:Path,env:dict,output:Path)->dict:
    source=validate_pr(pr)
    workflow=validate_owner_main_env(env)
    if output.exists() or output.is_symlink():
        raise EvidenceHold('RECEIPT_ALREADY_EXISTS_NO_OVERWRITE')
    ev=archive_evidence(archive)
    if ev['archive_filename']!=ARCHIVE_NAME or sha256(read_regular(binary,20*1024*1024)).hexdigest()!=ev['binary_sha256']:
        raise EvidenceHold('BUILD_BINARY_AND_ARCHIVE_NOT_EQUAL')
    receipt={'schema':SCHEMA,'target':source,
        'workflow':{'repository':REPOSITORY,'repository_id':REPOSITORY_ID,
                    'signer_workflow':SIGNER_WORKFLOW,**workflow},
        'artifact':ev,
        'tests':{'cargo_test_locked_passed':True,'cargo_release_build_locked_passed':True},
        'signed_by_this_script':False,
        'pr_head_signed_by_github':False,
        'deployment_digest_verified':False,
        'owner_deployment_acceptance_verified':False,
        'production_ready':False,'release_authorized':False,'action_authorized':False,
        'performed_external_mutations_by_script':False,
        'provenance_level':'UNSIGNED_MANIFEST_REQUIRES_INDEPENDENT_GITHUB_SIGSTORE_VERIFICATION'}
    output.write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
    return receipt


def validate_receipt(receipt:dict,pr:dict,archive:Path,env:dict)->dict:
    source=validate_pr(pr)
    workflow=validate_owner_main_env(env)
    ev=archive_evidence(archive)
    if ev['archive_filename']!=ARCHIVE_NAME:
        raise EvidenceHold('WRONG_SIGNING_INPUT_ARCHIVE_NAME')
    expected={'repository':REPOSITORY,'repository_id':REPOSITORY_ID,
              'signer_workflow':SIGNER_WORKFLOW,**workflow}
    if (not isinstance(receipt,dict) or receipt.get('schema')!=SCHEMA
        or receipt.get('target')!=source or receipt.get('workflow')!=expected
        or receipt.get('artifact')!=ev
        or receipt.get('tests')!={'cargo_test_locked_passed':True,
                                    'cargo_release_build_locked_passed':True}
        or receipt.get('provenance_level')!='UNSIGNED_MANIFEST_REQUIRES_INDEPENDENT_GITHUB_SIGSTORE_VERIFICATION'):
        raise EvidenceHold('SOURCE_RUN_ARTIFACT_TEST_RECEIPT_MISMATCH')
    for k in ('signed_by_this_script','pr_head_signed_by_github',
              'deployment_digest_verified','owner_deployment_acceptance_verified',
              'production_ready','release_authorized','action_authorized',
              'performed_external_mutations_by_script'):
        if receipt.get(k) is not False:
            raise EvidenceHold('FORGED_RELEASE_OR_PROVENANCE_AUTHORIZATION')
    if set(receipt)!={'schema','target','workflow','artifact','tests','signed_by_this_script',
                      'pr_head_signed_by_github','deployment_digest_verified',
                      'owner_deployment_acceptance_verified','production_ready',
                      'release_authorized','action_authorized',
                      'performed_external_mutations_by_script','provenance_level'}:
        raise EvidenceHold('UNRECOGNIZED_RECEIPT_FIELDS')
    return {'schema':SCHEMA,'pr_head':source['pr_head'],'signer_workflow_commit':workflow['source_commit'],
            'archive_sha256':ev['archive_sha256'],
            'status':'UNSIGNED_RECEIPT_SOURCE_AND_ARTIFACT_MATCHED_NOT_DEPLOYMENT',
            'attestation_verified':False,'production_ready':False}


def main(argv=None)->int:
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='action',required=True)
    pre=sub.add_parser('preflight')
    pre.add_argument('--pr-json',type=Path,required=True)
    mk=sub.add_parser('make')
    mk.add_argument('--pr-json',type=Path,required=True)
    mk.add_argument('--archive',type=Path,required=True)
    mk.add_argument('--binary',type=Path,required=True)
    mk.add_argument('--out',type=Path,required=True)
    verify=sub.add_parser('verify')
    verify.add_argument('--pr-json',type=Path,required=True)
    verify.add_argument('--archive',type=Path,required=True)
    verify.add_argument('--receipt',type=Path,required=True)
    args=p.parse_args(argv)
    try:
        original=read_json(args.pr_json)
        if args.action=='preflight':
            result=validate_pr(original)
            result['status']='EXACT_OPEN_DRAFT_PR_HEAD_MATCHED_NO_CI_DISPATCH'
        elif args.action=='make':
            result=make_receipt(original,args.archive,args.binary,os.environ,args.out)
            result={'status':'UNSIGNED_SOURCE_BOUND_BUILD_RECEIPT_READY',
                    'pr_head':result['target']['pr_head'],
                    'archive_sha256':result['artifact']['archive_sha256']}
        else:
            result=validate_receipt(read_json(args.receipt),original,args.archive,os.environ)
    except (EvidenceHold,KeyError,TypeError) as exc:
        p.error('HOLD_R39_'+str(exc))
    print(json.dumps(result,sort_keys=True))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
