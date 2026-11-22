"""R29 CI receipt producer: offline/synthetic fixtures; NEVER signs or dispatches CI."""
from __future__ import annotations
import importlib.util
import hashlib
import json
import pathlib
import tempfile
import unittest

CODE = pathlib.Path(__file__).with_name("r29_make_signed_ci_manifest.py")
SPEC = importlib.util.spec_from_file_location("r29_manifest_under_test", CODE)
m = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(m)

COMMIT="a242e5dbe348b01adeb8948e003b019a586bdf0d"
CANDIDATE="8"*40
COMPOSE="9"*64
def env():
    return {
        "GITHUB_ACTIONS":"true",
        "GITHUB_EVENT_NAME":"workflow_dispatch",
        "GITHUB_REPOSITORY":m.REPO,
        "GITHUB_REPOSITORY_ID":m.REPO_ID,
        "GITHUB_REF":"refs/heads/main",
        "GITHUB_ACTOR":"PeterxVarga",
        "GITHUB_TRIGGERING_ACTOR":"PeterxVarga",
        "GITHUB_SHA":COMMIT,
        "GITHUB_RUN_ID":"456789012",
        "GITHUB_RUN_ATTEMPT":"1",
    }
def digest(b): return hashlib.sha256(b).hexdigest()
def dump(path,obj):
    b=(json.dumps(obj,sort_keys=True,indent=2)+"\n").encode()
    path.write_bytes(b)
    return digest(b)

class R29ManifestTests(unittest.TestCase):
    def setUp(self):
        td=tempfile.TemporaryDirectory(prefix="r29-ci-offline-")
        self.addCleanup(td.cleanup)
        self.d=pathlib.Path(td.name)
        self.manifest=self.d/"r29-ci-run.receipt.json"
        checks=[]
        for svc,kind,passed in m.REQUIRED:
            name=f"receipt-{svc}-{kind}.json"
            raw={"schema":"tredven.upstream.system-test-receipt.v1",
                 "candidate_commit":CANDIDATE,
                 "compose_sha256":COMPOSE,
                 "service":svc,"kind":kind,
                 "result":"passed" if passed else "failed",
                 "tests_passed":int(passed),"tests_failed":int(not passed),
                 "isolated":True}
            value=dump(self.d/name,raw)
            checks.append({"name":name,"service":svc,"kind":kind,
                           "passed":passed,"sha256":value})
        self.run_record={
            "result":"REAL_APPLICATION_MIGRATION_COMPATIBLE_ROLLBACK_WITH_NEW_WRITES_BLOCKED",
            "app_source_commit":m.APP_COMMIT,
            "source_fixture_candidate_commit":CANDIDATE,
            "candidate_compose_sha256":COMPOSE,
            "baseline_message_count":2,"after_upgrade_message_count":4,
            "after_rollback_message_count":2,
            "rust_gate_decision":"BLOCKED",
            "one_click_upgrade_authorized":False,
            "post_cutover_new_writes_lost_on_rollback":True,
            "ci_signature_provenance":"UNSIGNED_LOCAL_NOT_GITHUB_HOSTED",
            "test_receipts":checks}
        dump(self.d/"r29-local-real-app-evidence.json",self.run_record)
        dump(self.d/"r29-real-app-rust-gate.json",{
            "decision":"BLOCKED","covered_required_checks":7,
            "total_required_checks":8,"one_click_live_upgrade_authorized":False})

    def test_offline_simulated_workflow_claim_is_not_a_signature(self):
        result=m.make(self.d,self.manifest,env=env())
        assert result["schema"]==m.SCHEMA
        assert len(result["receipt_hashes"])==8
        assert result["workflow"]["source_commit"]==COMMIT
        assert result["workflow"]["run_id"]=="456789012"
        assert result["workflow"]["run_attempt"]==1
        assert result["test_scope"]=="REAL_API_WORKER_PG16_TO17_ROLLBACK_LOSES_CANDIDATE_WRITES"
        self.assertNotIn("signature_verified",result)
        with self.assertRaisesRegex(RuntimeError,"ALREADY_EXISTS"):
            m.make(self.d,self.manifest,env=env())

    def test_no_user_dispatch_no_claim(self):
        for k,value in [
            ("GITHUB_ACTOR","outside-user"),
            ("GITHUB_TRIGGERING_ACTOR","outside-user"),
            ("GITHUB_REF","refs/heads/feature"),
            ("GITHUB_REPOSITORY_ID","123"),
        ]:
            with self.subTest(k=k):
                e=env();e[k]=value
                with self.assertRaisesRegex(RuntimeError,"NOT_OWNER"):
                    m.make(self.d,self.manifest,env=e)
        e=env();e["GITHUB_ACTIONS"]="false"
        with self.assertRaisesRegex(RuntimeError,"NOT_REVIEWED"):
            m.make(self.d,self.manifest,env=e)

    def test_missing_or_tampered_check_blocks_before_manifest(self):
        path=self.d/"receipt-db-rollback.json"
        path.write_bytes(path.read_bytes()+b"tamper")
        with self.assertRaisesRegex(RuntimeError,"REQUIRED_TEST_RECEIPT"):
            m.make(self.d,self.manifest,env=env())
        self.assertFalse(self.manifest.exists())

    def test_falsely_passed_rollback_never_claimed(self):
        self.run_record["post_cutover_new_writes_lost_on_rollback"]=False
        dump(self.d/"r29-local-real-app-evidence.json",self.run_record)
        with self.assertRaisesRegex(RuntimeError,"ACTUAL_E2E_CONTENT_CONTRADICTS"):
            m.make(self.d,self.manifest,env=env())

    def test_rust_gate_review_cannot_forge_signed_negative(self):
        path=self.d/"r29-real-app-rust-gate.json"
        data=json.loads(path.read_text());data["decision"]="REVIEW"
        dump(path,data)
        with self.assertRaisesRegex(RuntimeError,"RUST_POLICY_GATE_NOT_FAIL_CLOSED"):
            m.make(self.d,self.manifest,env=env())

if __name__=="__main__": unittest.main()
