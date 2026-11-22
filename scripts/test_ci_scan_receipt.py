"""R11 unsigned CI receipt construction tests; all local, no GitHub calls."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

P=Path(__file__).with_name("ci_scan_receipt.py")
SPEC=importlib.util.spec_from_file_location("r11_ci_receipt",P)
m=importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(m)

ENV={
    "GITHUB_ACTIONS":"true",
    "GITHUB_EVENT_NAME":"workflow_dispatch",
    "GITHUB_REPOSITORY":"PeterxVarga/tredven-upstream",
    "GITHUB_REPOSITORY_ID":"1467524521",
    "GITHUB_REF":"refs/heads/main",
    "GITHUB_SHA":"a1878d35a2b09ca36dcb39d136cf5ce86c1fe3cf",
    "GITHUB_RUN_ID":"10001",
    "GITHUB_RUN_ATTEMPT":"1",
}

class CiReceiptTests(unittest.TestCase):
    def setUp(self):
        root=os.environ.get("TREDVEN_R11_PUBLIC_REFERENCE_DIR")
        if root is None or not Path(root,"evidence","review.json").exists():
            self.skipTest("Explicit public R11 OSV evidence fixture not provided")
        self.tmp=tempfile.TemporaryDirectory(prefix="r11-signed-ci-generator-")
        self.addCleanup(self.tmp.cleanup)
        self.evidence=Path(self.tmp.name)/"evidence"
        shutil.copytree(Path(root)/"evidence",self.evidence)
        self.env=patch.dict(os.environ,ENV)
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_correct_ordinary_json_is_unsigned_even_with_github_env_vars(self):
        receipt=m.create_receipt(self.evidence,"attested-delivery/rust-template")
        self.assertEqual(receipt["schema"],m.SCHEMA)
        self.assertEqual(receipt["baseline"]["exit_code"],1)
        self.assertEqual(receipt["candidate"]["exit_code"],1)
        self.assertNotIn("signature",receipt)
        self.assertNotIn("production_ready",receipt)

    def test_missing_workflow_dispatch_context_refused(self):
        os.environ["GITHUB_EVENT_NAME"]="push"
        with self.assertRaisesRegex(ValueError,"INVALID_GITHUB_CONTEXT"):
            m.create_receipt(self.evidence,"attested-delivery/rust-template")

    def test_wrong_signing_repository_or_id_refused(self):
        os.environ["GITHUB_REPOSITORY_ID"]="999999"
        with self.assertRaisesRegex(ValueError,"UNEXPECTED_SIGNING_REPOSITORY_ID"):
            m.create_receipt(self.evidence,"attested-delivery/rust-template")

    def test_unreviewed_branch_dispatch_is_not_qualified_for_signing(self):
        os.environ["GITHUB_REF"]="refs/heads/unreviewed-feature"
        with self.assertRaisesRegex(ValueError,"UNEXPECTED_SIGNER_SOURCE_REF"):
            m.create_receipt(self.evidence,"attested-delivery/rust-template")

    def test_public_scanned_repo_cannot_be_substituted(self):
        with self.assertRaisesRegex(ValueError,"UNEXPECTED_PUBLIC_SCANNED_REPOSITORY"):
            m.create_receipt(self.evidence,"customer/private-repo")

    def test_tampered_scanner_json_digest_refused(self):
        p=self.evidence/"candidate.scanner.json"
        p.write_bytes(p.read_bytes()+b" ")
        with self.assertRaisesRegex(ValueError,"SCANNED_ARTIFACT_BYTES_MISMATCH"):
            m.create_receipt(self.evidence,"attested-delivery/rust-template")

    def test_tampered_lockfile_digest_refused(self):
        p=self.evidence/"baseline.Cargo.lock"
        p.write_bytes(p.read_bytes()+b"\n")
        with self.assertRaisesRegex(ValueError,"SCANNED_ARTIFACT_BYTES_MISMATCH"):
            m.create_receipt(self.evidence,"attested-delivery/rust-template")

    def test_unobserved_scanner_exit_refused(self):
        p=self.evidence/"review.json";r=json.loads(p.read_text())
        r["baseline"]["local_execution_observed"]=False
        p.write_text(json.dumps(r))
        with self.assertRaisesRegex(ValueError,"SCANNER_EXIT_STATUS_NOT_OBSERVED"):
            m.create_receipt(self.evidence,"attested-delivery/rust-template")

    def test_forged_source_commit_refused(self):
        p=self.evidence/"review.json";r=json.loads(p.read_text())
        r["source"]["baseline_commit"]="0"*40
        p.write_text(json.dumps(r))
        with self.assertRaisesRegex(ValueError,"SCANNED_SOURCE_TAG_AND_COMMIT_MISMATCH"):
            m.create_receipt(self.evidence,"attested-delivery/rust-template")

    def test_missing_run_id_refused(self):
        os.environ.pop("GITHUB_RUN_ID",None)
        with self.assertRaisesRegex(ValueError,"INVALID_GITHUB_CONTEXT_GITHUB_RUN_ID"):
            m.create_receipt(self.evidence,"attested-delivery/rust-template")

if __name__=="__main__":
    unittest.main(verbosity=2)
