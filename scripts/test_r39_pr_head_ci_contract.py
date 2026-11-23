"""R39 exact PR10 owner/manual source-to-unsigned-receipt contract guards."""
from __future__ import annotations
from copy import deepcopy
from hashlib import sha256
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from scripts import r39_pr_head_ci_contract as r39

REPO=Path(__file__).resolve().parents[1]
YAML=REPO/'.github/workflows/r39-manual-pr-head-ci.yml'


def sample_pr():
    return {'number':10,'state':'open','draft':True,
            'html_url':'https://github.com/PeterxVarga/tredven-upstream/pull/10',
            'head':{'sha':r39.PR_HEAD,'ref':r39.PR_BRANCH,'repo':{
                'id':r39.REPOSITORY_ID,'full_name':r39.REPOSITORY}},
            'base':{'sha':r39.PR_BASE,'ref':r39.BASE_BRANCH,
                    'repo':{'id':r39.REPOSITORY_ID,'full_name':r39.REPOSITORY}}}


def sample_env():
    return {'GITHUB_ACTIONS':'true','GITHUB_EVENT_NAME':'workflow_dispatch',
            'GITHUB_REPOSITORY':r39.REPOSITORY,
            'GITHUB_REPOSITORY_ID':str(r39.REPOSITORY_ID),
            'GITHUB_REF':'refs/heads/main',
            'GITHUB_ACTOR':'PeterxVarga','GITHUB_TRIGGERING_ACTOR':'PeterxVarga',
            'GITHUB_SHA':'6'*40,'GITHUB_RUN_ID':'12345678901','GITHUB_RUN_ATTEMPT':'1'}


def fake_archive(path:Path, binary:bytes=b'R39_SYNTHETIC_NOT_A_RUST_BINARY'):
    with tarfile.open(path,'w:gz') as tf:
        t=tarfile.TarInfo('tredven-upstream');t.size=len(binary);t.mode=0o755
        tf.addfile(t,io.BytesIO(binary))


class R39ContractTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='r39-offline-')
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.original=sample_pr()
        self.env=sample_env()
        self.pr_path=self.root/'original-pr.json'
        self.pr_path.write_text(json.dumps(self.original))
        self.binary=self.root/'tredven-upstream'
        self.binary.write_bytes(b'R39_SYNTHETIC_NOT_A_RUST_BINARY')
        self.archive=self.root/r39.ARCHIVE_NAME
        fake_archive(self.archive,self.binary.read_bytes())
        self.receipt=self.root/r39.RECEIPT_NAME

    def make(self):
        return r39.make_receipt(self.original,self.archive,self.binary,self.env,self.receipt)

    def test_exact_public_pr10_original_identity(self):
        value=r39.validate_pr(self.original)
        self.assertEqual(value['pr_head'],r39.PR_HEAD)
        self.assertEqual(value['pr_base'],r39.PR_BASE)
        self.assertEqual(value['repository_id'],r39.REPOSITORY_ID)

    def test_changed_pr_or_base_or_repo_fails_closed(self):
        cases={
            'head_sha':lambda x:x['head'].__setitem__('sha','7'*40),
            'base_sha':lambda x:x['base'].__setitem__('sha','7'*40),
            'non_draft':lambda x:x.__setitem__('draft',False),
            'closed':lambda x:x.__setitem__('state','closed'),
            'foreign_head_repo':lambda x:x['head']['repo'].__setitem__('full_name','attacker/fork'),
            'wrong_repository_id':lambda x:x['head']['repo'].__setitem__('id',1),
            'pr_number':lambda x:x.__setitem__('number',11),
            'head_ref':lambda x:x['head'].__setitem__('ref','another-branch'),
            'base_ref':lambda x:x['base'].__setitem__('ref','main'),
        }
        for name,change in cases.items():
            x=deepcopy(self.original);change(x)
            with self.subTest(name=name),self.assertRaises(r39.EvidenceHold):r39.validate_pr(x)

    def test_owner_main_dispatched_identity_exactly_required(self):
        v=r39.validate_owner_main_env(self.env)
        self.assertEqual(v['source_ref'],'refs/heads/main')
        self.assertEqual(v['run_attempt'],1)
        for k,bad in [('GITHUB_ACTIONS','false'),('GITHUB_REPOSITORY','wrong/repo'),
                      ('GITHUB_REPOSITORY_ID','99'),('GITHUB_REF','refs/heads/feature'),
                      ('GITHUB_EVENT_NAME','push'),('GITHUB_ACTOR','stranger'),
                      ('GITHUB_TRIGGERING_ACTOR','stranger'),('GITHUB_SHA','ABC'),
                      ('GITHUB_RUN_ID','0'),('GITHUB_RUN_ATTEMPT','0')]:
            x={**self.env,k:bad}
            with self.subTest(field=k),self.assertRaises(r39.EvidenceHold):
                r39.validate_owner_main_env(x)

    def test_offline_synthetic_issue_and_verify_still_unsigned(self):
        x=self.make()
        self.assertEqual(x['target']['pr_head'],r39.PR_HEAD)
        self.assertEqual(x['workflow']['signer_workflow'],r39.SIGNER_WORKFLOW)
        self.assertEqual(x['artifact']['archive_sha256'],sha256(self.archive.read_bytes()).hexdigest())
        self.assertEqual(x['artifact']['binary_sha256'],sha256(self.binary.read_bytes()).hexdigest())
        self.assertFalse(x['signed_by_this_script'])
        self.assertFalse(x['pr_head_signed_by_github'])
        self.assertFalse(x['production_ready'])
        y=r39.validate_receipt(x,self.original,self.archive,self.env)
        self.assertEqual(y['status'],'UNSIGNED_RECEIPT_SOURCE_AND_ARTIFACT_MATCHED_NOT_DEPLOYMENT')
        self.assertFalse(y['attestation_verified'])

    def test_receipt_rejects_future_claims_as_verified_without_sigstore(self):
        x=self.make()
        for key in ('signed_by_this_script','pr_head_signed_by_github',
                    'deployment_digest_verified','owner_deployment_acceptance_verified',
                    'production_ready','release_authorized','action_authorized'):
            y={**x,key:True}
            with self.subTest(key=key),self.assertRaises(r39.EvidenceHold):
                r39.validate_receipt(y,self.original,self.archive,self.env)

    def test_receipt_rejects_tampered_source_run_archive_and_tests(self):
        x=self.make()
        cases=[('target_head',lambda y:y['target'].__setitem__('pr_head','7'*40)),
               ('workflow_run',lambda y:y['workflow'].__setitem__('run_id','7')),
               ('workflow_source',lambda y:y['workflow'].__setitem__('source_commit','8'*40)),
               ('artifact_sha',lambda y:y['artifact'].__setitem__('archive_sha256','f'*64)),
               ('binary_sha',lambda y:y['artifact'].__setitem__('binary_sha256','a'*64)),
               ('tests',lambda y:y['tests'].__setitem__('cargo_test_locked_passed',False)),
               ('foreign_fields',lambda y:y.__setitem__('verified_buyer',True))]
        for key,change in cases:
            y=deepcopy(x);change(y)
            with self.subTest(test=key),self.assertRaises(r39.EvidenceHold):
                r39.validate_receipt(y,self.original,self.archive,self.env)

    def test_archive_bytes_must_match_receipt_and_compiled_binary(self):
        self.make()
        self.archive.write_bytes(self.archive.read_bytes()+b'untrusted appended bytes')
        with self.assertRaises(r39.EvidenceHold):
            r39.validate_receipt(r39.read_json(self.receipt),self.original,self.archive,self.env)

    def test_archive_with_extra_member_or_symlink_refused(self):
        with tarfile.open(self.archive,'w:gz') as tf:
            for name in ('tredven-upstream','leak-secret.txt'):
                b=b'synthetic'
                t=tarfile.TarInfo(name);t.size=len(b)
                tf.addfile(t,io.BytesIO(b))
        with self.assertRaises(r39.EvidenceHold):r39.archive_evidence(self.archive)
        self.archive.unlink()
        self.archive.symlink_to(self.binary)
        with self.assertRaises(r39.EvidenceHold):r39.archive_evidence(self.archive)

    def test_make_refuses_preexisting_receipt_without_mutation(self):
        self.receipt.write_text('DO_NOT_OVERWRITE')
        with self.assertRaises(r39.EvidenceHold):self.make()
        self.assertEqual(self.receipt.read_text(),'DO_NOT_OVERWRITE')

    def test_real_preflight_cli_only_original_source_bytes(self):
        from contextlib import redirect_stdout
        import io as _io
        with redirect_stdout(_io.StringIO()) as output:
            result=r39.main(['preflight','--pr-json',str(self.pr_path)])
        self.assertEqual(result,0)
        self.assertIn('EXACT_OPEN_DRAFT_PR_HEAD_MATCHED_NO_CI_DISPATCH',output.getvalue())
        self.assertFalse(self.receipt.exists())

    def test_binary_change_cannot_enter_unsigned_receipt(self):
        self.binary.write_bytes(b'not-the-original-bytes')
        with self.assertRaises(r39.EvidenceHold):self.make()
        self.assertFalse(self.receipt.exists())

    def test_static_yaml_only_owner_main_manual_and_split_job_rights(self):
        try:
            import yaml
        except ImportError:
            self.skipTest('optional PyYAML unavailable: runtime still stdlib-only')
        wf=yaml.load(YAML.read_text(),Loader=yaml.BaseLoader)
        self.assertEqual(set(wf['on']),{'workflow_dispatch'})
        self.assertEqual(wf['permissions'],{'contents':'read'})
        self.assertEqual(set(wf['jobs']),{'build-pr10-head','attest-only-after-build'})
        build=wf['jobs']['build-pr10-head']
        sign=wf['jobs']['attest-only-after-build']
        self.assertEqual(build['permissions'],{'contents':'read','pull-requests':'read'})
        self.assertEqual(sign['permissions'],{'contents':'read','pull-requests':'read','id-token':'write','attestations':'write'})
        self.assertEqual(sign['needs'],'build-pr10-head')
        for job in (build,sign):
            predicate=job['if']
            self.assertIn("github.ref == 'refs/heads/main'",predicate)
            self.assertIn("github.actor == 'PeterxVarga'",predicate)
            self.assertIn("github.triggering_actor == 'PeterxVarga'",predicate)
            self.assertIn("github.event_name == 'workflow_dispatch'",predicate)
        text=YAML.read_text()
        self.assertIn(f'ref: {r39.PR_HEAD}',text)
        self.assertIn('python3 -I -B scripts/r39_pr_head_ci_contract.py verify',text)
        self.assertIn('cargo +1.100.0 test --locked',text)
        self.assertIn('cargo +1.100.0 build --locked --release',text)
        self.assertEqual(text.count('actions/attest-build-provenance@'),2)
        self.assertEqual(text.count('actions/download-artifact@'),1)
        self.assertEqual(text.count('actions/upload-artifact@'),2)
        self.assertNotIn('github.event_name == \'push\'',text)
        self.assertNotIn('gh release create',text)
        self.assertNotIn('gh workflow run',text)
        self.assertNotIn('docker push',text)
        self.assertNotIn('kubectl apply',text)
        for label in ('actions/checkout@','actions/attest-build-provenance@',
                      'actions/upload-artifact@','actions/download-artifact@'):
            import re
            for match in re.finditer(re.escape(label)+r'([^\s]+)',text):
                self.assertRegex(match.group(1),r'^[0-9a-f]{40}$')

    def test_signer_job_never_checks_out_untrusted_pr_commit(self):
        try:import yaml
        except ImportError:self.skipTest('PyYAML optional')
        wf=yaml.load(YAML.read_text(),Loader=yaml.BaseLoader)
        sign=wf['jobs']['attest-only-after-build']
        self.assertTrue(all(
            step.get('with',{}).get('ref') != r39.PR_HEAD
            for step in sign['steps']))
        self.assertTrue(all('actions/checkout@' not in step.get('uses','') or
                            step.get('with',{}).get('persist-credentials')=='false'
                            for step in sign['steps']))
        self.assertTrue(any('scripts/r39_pr_head_ci_contract.py verify' in
                            step.get('run','') for step in sign['steps']))
        self.assertTrue(any('actions/attest-build-provenance@' in
                            step.get('uses','') for step in sign['steps']))


if __name__=='__main__':unittest.main()
