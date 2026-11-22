#!/usr/bin/env python3
"""R29 signed-CI manifest *producer*. This does NOT perform signing.

Runs only in a GitHub-hosted, owner-dispatched reviewed main workflow.
It binds the exact SHA of the real application E2E and 8 source-bound
test receipts plus the Rust fail-closed decision to one workflow identity.
GitHub/Sigstore signing is performed separately by actions/attest.
"""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, re, sys

REPO="PeterxVarga/tredven-upstream"
REPO_ID="1467524521"
WORKFLOW=REPO+"/.github/workflows/r29-manual-real-app-ci.yml"
SCHEMA="tredven.upstream.r29.signed-system-ci-manifest.v1"
APP_COMMIT="417de5b4c3e2741853944fbf97a9988de48d647d"
REQUIRED=[("api","health",True),("api","integration",True),
          ("db","health",True),("db","integration",True),
          ("db","data-migration",True),("db","rollback",False),
          ("worker","health",True),("worker","integration",True)]

def sha(buf):return hashlib.sha256(buf).hexdigest()
def filebytes(path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("MISSING_OR_UNSAFE_CI_INPUT_FILE:"+path.name)
    buf=path.read_bytes()
    if not 0<len(buf)<=2*1024*1024:
        raise RuntimeError("INVALID_CI_INPUT_SIZE:"+path.name)
    return buf

def make(evidence_dir:pathlib.Path, destination:pathlib.Path, *,env:dict)->dict:
    if env.get("GITHUB_ACTIONS")!="true" or env.get("GITHUB_EVENT_NAME")!="workflow_dispatch":
        raise RuntimeError("NOT_REVIEWED_GITHUB_HOSTED_MANUAL_RUN")
    if (env.get("GITHUB_REPOSITORY")!=REPO or env.get("GITHUB_REPOSITORY_ID")!=REPO_ID
        or env.get("GITHUB_REF")!="refs/heads/main"
        or env.get("GITHUB_ACTOR")!="PeterxVarga"
        or env.get("GITHUB_TRIGGERING_ACTOR")!="PeterxVarga"):
        raise RuntimeError("NOT_OWNER_DISPATCHED_APPROVED_MAIN")
    commit=env.get("GITHUB_SHA","")
    run_id=env.get("GITHUB_RUN_ID","")
    attempt=env.get("GITHUB_RUN_ATTEMPT","")
    if not re.fullmatch(r"[0-9a-f]{40}",commit) or not re.fullmatch(r"[1-9][0-9]{0,23}",run_id):
        raise RuntimeError("INVALID_HOSTED_WORKFLOW_IDENTITY")
    if not attempt.isdecimal() or not 1<=int(attempt)<=1000:
        raise RuntimeError("INVALID_WORKFLOW_ATTEMPT")
    report=filebytes(evidence_dir/"r29-local-real-app-evidence.json")
    run=json.loads(report)
    if (run.get("result")!="REAL_APPLICATION_MIGRATION_COMPATIBLE_ROLLBACK_WITH_NEW_WRITES_BLOCKED"
        or run.get("app_source_commit")!=APP_COMMIT
        or run.get("baseline_message_count")!=2
        or run.get("after_upgrade_message_count")!=4
        or run.get("after_rollback_message_count")!=2
        or run.get("rust_gate_decision")!="BLOCKED"
        or run.get("one_click_upgrade_authorized") is not False
        or run.get("post_cutover_new_writes_lost_on_rollback") is not True
        or run.get("ci_signature_provenance")!="UNSIGNED_LOCAL_NOT_GITHUB_HOSTED"):
        raise RuntimeError("ACTUAL_E2E_CONTENT_CONTRADICTS_EXPECTED_RESULT")
    expected={f"receipt-{service}-{kind}.json" for service,kind,_ in REQUIRED}
    checks=run.get("test_receipts")
    if not isinstance(checks,list) or len(checks)!=8 or {x.get("name") for x in checks}!=expected:
        raise RuntimeError("TEST_RECEIPT_SCOPE_INCOMPLETE")
    receipts=[]
    for service,kind,must_pass in REQUIRED:
        name=f"receipt-{service}-{kind}.json"
        data=filebytes(evidence_dir/name)
        matching=next(x for x in checks if x["name"]==name)
        if matching.get("sha256")!=sha(data):
            raise RuntimeError("REQUIRED_TEST_RECEIPT_BYTES_OR_OUTCOME_CONTRADICT")
        item=json.loads(data)
        if (item.get("schema")!="tredven.upstream.system-test-receipt.v1"
            or item.get("candidate_commit")!=run["source_fixture_candidate_commit"]
            or item.get("compose_sha256")!=run["candidate_compose_sha256"]
            or item.get("service")!=service or item.get("kind")!=kind
            or (item.get("result")=="passed")!=must_pass
            or item.get("tests_passed")!=int(must_pass)
            or item.get("tests_failed")!=int(not must_pass)
            or item.get("isolated") is not True
            or matching.get("sha256")!=sha(data)
            or matching.get("passed")!=must_pass):
            raise RuntimeError("REQUIRED_TEST_RECEIPT_BYTES_OR_OUTCOME_CONTRADICT")
        receipts.append({"name":name,"sha256":sha(data)})
    raw_gate=filebytes(evidence_dir/"r29-real-app-rust-gate.json")
    gate=json.loads(raw_gate)
    if (gate.get("decision")!="BLOCKED"
        or gate.get("covered_required_checks")!=7
        or gate.get("total_required_checks")!=8
        or gate.get("one_click_live_upgrade_authorized") is not False):
        raise RuntimeError("RUST_POLICY_GATE_NOT_FAIL_CLOSED")
    envelope={
       "schema":SCHEMA,
       "workflow":{
           "repository":REPO,"repository_id":REPO_ID,
           "signer_workflow":WORKFLOW,
           "source_ref":"refs/heads/main","source_commit":commit,
           "run_id":run_id,"run_attempt":int(attempt)
       },
       "run_evidence_sha256":sha(report),
       "rust_gate_report_sha256":sha(raw_gate),
       "receipt_hashes":receipts,
       "public_app_source_commit":APP_COMMIT,
       "candidate_compose_sha256":run["candidate_compose_sha256"],
       "candidate_commit":run["source_fixture_candidate_commit"],
       "test_scope":"REAL_API_WORKER_PG16_TO17_ROLLBACK_LOSES_CANDIDATE_WRITES"
    }
    if destination.exists() or destination.is_symlink():
        raise RuntimeError("CI_SIGNING_INPUT_ALREADY_EXISTS")
    destination.write_bytes((json.dumps(envelope,sort_keys=True,indent=2)+"\n").encode())
    return envelope

def main():
    a=argparse.ArgumentParser()
    a.add_argument("--evidence-dir",type=pathlib.Path,required=True)
    a.add_argument("--out",type=pathlib.Path,required=True)
    args=a.parse_args()
    result=make(args.evidence_dir,args.out,env=os.environ)
    print(json.dumps({"status":"UNSIGNED_CI_CLAIM_READY_FOR_GH_ACTIONS_ATTEST",
        "ci_source_commit":result["workflow"]["source_commit"],
        "artifact_sha256":sha(filebytes(args.out)),
        "underlying_upgrade_decision":"BLOCKED"},sort_keys=True))

if __name__=="__main__":
    try:main()
    except (RuntimeError,KeyError,ValueError) as e:
        print("BLOCKED_R29_CI_MANIFEST:"+str(e),file=sys.stderr)
        sys.exit(2)
