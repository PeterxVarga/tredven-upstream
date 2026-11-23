"""Synthetic-only R39 dual Rust signer consumer falsification; NOT actual signed CI."""
from __future__ import annotations
from copy import deepcopy
from hashlib import sha256
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from scripts import r39_pr_head_ci_contract as c
from scripts import r39_verify_signed_pr_head as v
from scripts.test_r39_pr_head_ci_contract import sample_pr, sample_env, fake_archive

RUN_ID=12345678901
RUN_SHA='6'*40


def fake_run():
    return {'id':RUN_ID,'event':'workflow_dispatch','head_branch':'main',
            'path':v.RUN_PATH,'status':'completed','conclusion':'success',
            'repository':{'full_name':c.REPOSITORY,'id':c.REPOSITORY_ID},
            'actor':{'login':'PeterxVarga'},
            'triggering_actor':{'login':'PeterxVarga'},
            'run_attempt':1,'head_sha':RUN_SHA}


def original_rust_report(name,sha):
    return {'schema':'tredven.upstream.gh-artifact-attestation.v1',
            'verdict':'VERIFIED','reason':'SIGNED_ARTIFACT_PROVENANCE_AND_EXACT_IDENTITY_VERIFIED',
            'artifact_filename':name,'artifact_sha256':sha,
            'repo':c.REPOSITORY,'repository_id':str(c.REPOSITORY_ID),
            'signer_workflow':c.SIGNER_WORKFLOW,
            'source_ref':'refs/heads/main','source_commit':RUN_SHA,
            'verified_workflow_run_uri':f'https://github.com/{c.REPOSITORY}/actions/runs/{RUN_ID}/attempts/1',
            'signatures_cryptographically_verified_by_gh':True,
            'validated_certificate_source_identity':True,
            'trusted_timestamp_observed':True,
            'scanner_execution_verified':False,'production_ready':False,
            'release_authorized':False,'action_authorized':False,
            'performed_mutations':False}


class SignedR39ConsumerTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(prefix='r39-synthetic-verification-')
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.pr=sample_pr()
        self.run=fake_run()
        self.env=sample_env()
        self.archive=self.root/c.ARCHIVE_NAME
        self.binary=self.root/'tredven-upstream'
        self.binary.write_bytes(b'SYNTHETIC_NOT_COMPILED_RUST')
        fake_archive(self.archive,self.binary.read_bytes())
        self.receipt=self.root/c.RECEIPT_NAME
        c.make_receipt(self.pr,self.archive,self.binary,self.env,self.receipt)
        self.ra=original_rust_report(self.archive.name,sha256(self.archive.read_bytes()).hexdigest())
        self.rr=original_rust_report(self.receipt.name,sha256(self.receipt.read_bytes()).hexdigest())

    def test_exact_original_run_owner_main_metadata_required(self):
        env=v.env_from_official_run(self.run,RUN_ID)
        self.assertEqual(env,self.env)
        cases={'workflow':('path','wrong.yml'),
               'state':('status','queued'),
               'conclusion':('conclusion','failure'),
               'head':('head_branch','feature'),
               'event':('event','push'),
               'owner':('actor',{'login':'unauthorized'}),
               'triggering':('triggering_actor',{'login':'unauthorized'}),
               'repo':('repository',{'id':999,'full_name':c.REPOSITORY}),
               'run_id':('id',10),
               'sha':('head_sha','bad')}
        for name,(k,bad) in cases.items():
            with self.subTest(case=name):
                x=deepcopy(self.run);x[k]=bad
                with self.assertRaises(c.EvidenceHold):v.env_from_official_run(x,RUN_ID)

    def test_both_strict_signatures_required_for_positive(self):
        self.assertTrue(v.verify_native_report(self.ra,artifact=self.archive,
            sha=sha256(self.archive.read_bytes()).hexdigest(),run=self.run))
        self.assertTrue(v.verify_native_report(self.rr,artifact=self.receipt,
            sha=sha256(self.receipt.read_bytes()).hexdigest(),run=self.run))

    def test_wrong_signer_digest_run_uri_certificate_flags_or_release_refused(self):
        candidates={'wrong_signer':('signer_workflow','another/repo/.github/workflows/x.yml'),
            'wrong_source':('source_commit','7'*40),
            'wrong_ref':('source_ref','refs/heads/feature'),
            'wrong_run':('verified_workflow_run_uri','https://github.com/another/run'),
            'wrong_digest':('artifact_sha256','0'*64),
            'wrong_filename':('artifact_filename','other.tar.gz'),
            'fake_crypto':('signatures_cryptographically_verified_by_gh',False),
            'fake_cert':('validated_certificate_source_identity',False),
            'missing_timestamp':('trusted_timestamp_observed',False),
            'release':('release_authorized',True),
            'deployment':('production_ready',True),
            'workflow_mutation':('performed_mutations',True)}
        for name,(field,val) in candidates.items():
            with self.subTest(case=name):
                candidate={**self.ra,field:val}
                self.assertFalse(v.verify_native_report(candidate,artifact=self.archive,
                  sha=sha256(self.archive.read_bytes()).hexdigest(),run=self.run))

    def test_synthetic_qualify_full_adapter_cannot_claim_deployment(self):
        def fake_get(gh,endpoint,run_id):
            return deepcopy(self.pr if endpoint.endswith('/pulls/10') else self.run)
        def fake_sig(verifier,gh,artifact,run):
            return self.ra if artifact==self.archive else self.rr
        with patch.object(v,'check_tools'),patch.object(v,'original_gh',side_effect=fake_get),\
             patch.object(v,'verify_one',side_effect=fake_sig) as verifications:
            result=v.qualify(run_id=RUN_ID,gh=Path('/mock/gh'),
                    verifier=Path('/mock/rust'),archive=self.archive,receipt=self.receipt)
        self.assertEqual(verifications.call_count,2)
        self.assertEqual(result['decision'],
                         'SIGNED_PR_HEAD_BUILD_AND_RECEIPT_VERIFIED_NO_DEPLOYMENT_AUTHORITY')
        self.assertTrue(result['ci_source_and_artifact_provenance_verified'])
        self.assertFalse(result['deployment_artifact_digest_verified'])
        self.assertFalse(result['owner_deployment_acceptance_verified'])
        self.assertFalse(result['actual_upgrade_compatibility_verified'])
        self.assertFalse(result['production_ready'])
        self.assertFalse(result['performed_mutations'])

    def test_single_false_rust_signature_blocks_entire_join(self):
        with patch.object(v,'check_tools'),\
             patch.object(v,'original_gh',side_effect=lambda gh,endpoint,run_id:
                self.pr if endpoint.endswith('/pulls/10') else self.run),\
             patch.object(v,'verify_one',side_effect=[self.ra,{**self.rr,'verdict':'BLOCKED'}]):
            result=v.qualify(run_id=RUN_ID,gh=Path('/mock/gh'),
                verifier=Path('/mock/rust'),archive=self.archive,receipt=self.receipt)
        self.assertEqual(result['decision'],'HOLD_PR_HEAD_SIGNATURES_OR_WORKFLOW_SOURCE_NOT_BOTH_VERIFIED')
        self.assertFalse(result['ci_source_and_artifact_provenance_verified'])

    def test_unrelated_signed_r20_run_never_qualifies_as_r39(self):
        prior={**fake_run(),'path':'.github/workflows/r20-manual-alpha-provenance.yml',
                'id':45059405597}
        with self.assertRaises(c.EvidenceHold):
            v.env_from_official_run(prior,45059405597)

    def test_exact_allowlisted_github_reads_only(self):
        with patch.object(v,'subprocess_json',return_value={'test':'GET'}) as spy:
            actual=v.original_gh(Path('/safe/gh'),f'repos/{c.REPOSITORY}/pulls/10',RUN_ID)
            self.assertEqual(actual,{'test':'GET'})
            self.assertEqual(spy.call_args.args[0][:4],['/safe/gh','api','-X','GET'])
        for url in (f'repos/{c.REPOSITORY}/issues/10',
                    f'repos/{c.REPOSITORY}/actions/workflows/r39.yml/dispatches',
                    'repos/private/secret/pulls/10'):
            with self.subTest(endpoint=url),self.assertRaises(c.EvidenceHold):
                v.original_gh(Path('/mock/gh'),url,RUN_ID)

    def test_unqualified_executable_or_symlink_not_a_signature_verifier(self):
        binary=self.root/'trusted';binary.write_bytes(b'NOT_QUALIFIED')
        binary.chmod(0o700)
        with self.assertRaises(c.EvidenceHold):
            v.check_tools(binary,binary)
        link=self.root/'unsafe';link.symlink_to(binary)
        with self.assertRaises(c.EvidenceHold):v.executable_digest(link)

    def test_gh_cli_source_failure_does_not_leak_provider_stderr(self):
        denied=subprocess.CompletedProcess(['gh'],1,stdout='{"message":"Denied"}',stderr='TOP_SECRET_TOKEN')
        with patch('subprocess.run',return_value=denied):
            with self.assertRaises(c.EvidenceHold) as ctx:
                v.subprocess_json(['gh','api','-X','GET','safe'])
            self.assertNotIn('TOP_SECRET_TOKEN',str(ctx.exception))

    def test_no_output_overwrite_or_unauthorized_partial_write(self):
        dest=self.root/'existing';dest.mkdir()
        with patch.object(v,'qualify',side_effect=AssertionError('must not run')):
            with self.assertRaises(SystemExit):v.main([
                '--run-id',str(RUN_ID),'--archive',str(self.archive),
                '--receipt',str(self.receipt),'--rust-verifier','/mock',
                '--qualified-gh','/mock','--output-dir',str(dest)])
        self.assertEqual(list(dest.iterdir()),[])


if __name__=='__main__':unittest.main()
