"""R38: falsify PR/run/source/attestation/deployment/acceptance with no network."""
from __future__ import annotations
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import r38_pr_build_deployment_probe as r38

PR_SHA='1c8a15ad84858bead99b88e655915975ceefb2e9'
RUN_SHA='61d1a12d88e822fdfa6ba652115cbf06132614df'
PR=10
RUN=45059405597
ARCHIVE='tredven-upstream-v0.1.0-x86_64-unknown-linux-musl.tar.gz'
ARCHIVE_SHA='ce0524378e0aad328e04813a9003b2211b7c6d24ee7c3fcc87e7ac0e28264a66'
RUN_URL=f'https://github.com/{r38.REPO}/actions/runs/{RUN}'


def record():
    pr={'number':PR,'state':'open','draft':True,
        'html_url':f'https://github.com/{r38.REPO}/pull/{PR}',
        'head':{'sha':PR_SHA,'repo':{'full_name':r38.REPO}},
        'base':{'sha':'44d6eef16de40e33474e578c0ffcd7a2e1b4c698'}}
    run={'id':RUN,'head_sha':RUN_SHA,'head_branch':'main','status':'completed',
         'conclusion':'success','path':r38.WORKFLOW_PATH,'event':'workflow_dispatch',
         'repository':{'id':r38.REPO_ID,'full_name':r38.REPO},'run_attempt':1}
    artifacts={'total_count':2,'artifacts':[
        {'name':name,'expired':False,'digest':'sha256:'+'f'*64,
         'workflow_run':{'head_sha':RUN_SHA,'id':RUN}}
        for name in ('r20-alpha-candidate-bytes','r20-alpha-attestation-bundle')]}
    checks={'total_count':0,'check_runs':[]}
    deployments=[]
    native={'schema':'tredven.upstream.gh-artifact-attestation.v1','verdict':'VERIFIED',
            'artifact_filename':ARCHIVE,'artifact_sha256':ARCHIVE_SHA,'repo':r38.REPO,
            'repository_id':str(r38.REPO_ID),'source_commit':RUN_SHA,'source_ref':'refs/heads/main',
            'signer_workflow':r38.SIGNER,
            'verified_workflow_run_uri':RUN_URL+'/attempts/1',
            'signatures_cryptographically_verified_by_gh':True,
            'validated_certificate_source_identity':True,'trusted_timestamp_observed':True,
            'production_ready':False,'release_authorized':False,
            'action_authorized':False,'performed_mutations':False}
    manifest={'schema':'tredven.upstream.local-release-candidate.v2',
              'source_commit':RUN_SHA,'artifacts':{'archive':{'filename':ARCHIVE,'sha256':ARCHIVE_SHA}},
              'production_ready':False,'publication_authorized':False,'signature_verified':False}
    return dict(pr=pr,run=run,artifacts=artifacts,checks=checks,
                deployments=deployments,native=native,manifest=manifest,
                archive_name=ARCHIVE,archive_sha=ARCHIVE_SHA,pr_number=PR,run_id=RUN)


class R38EvidenceChainTests(unittest.TestCase):
    def test_real_shape_synthetic_mismatch_fails_to_promote(self):
        r=r38.assess(**record())
        self.assertEqual(r['decision'],'HOLD_PR_TO_SIGNED_BUILD_SOURCE_MISMATCH')
        self.assertTrue(r['signed_artifact']['cryptographic_provenance_verified_by_existing_rust'])
        self.assertFalse(r['source_binding']['pr_head_equals_signed_run_source'])
        self.assertFalse(r['source_binding']['pr_has_matching_run_check'])
        self.assertEqual(r['stages']['deployment'],'NO_MATCHING_GITHUB_DEPLOYMENT_EXTERNAL_UNKNOWN')
        self.assertFalse(r['deployment_digest_verified'])
        self.assertFalse(r['owner_acceptance_verified'])
        self.assertIsNone(r['commercial_winner'])
        self.assertFalse(r['performed_external_mutations'])
        self.assertNotIn('password',json.dumps(r))

    def test_matching_pr_sha_without_pr_ci_check_still_hold(self):
        x=record();x['pr']['head']['sha']=RUN_SHA
        out=r38.assess(**x)
        self.assertEqual(out['decision'],'HOLD_SIGNED_BUILD_OR_PR_CHECK_UNPROVEN')
        self.assertFalse(out['source_binding']['pr_has_matching_run_check'])

    def test_matching_pr_check_cannot_claim_a_real_deployment(self):
        x=record();x['pr']['head']['sha']=RUN_SHA
        x['checks']={'total_count':1,'check_runs':[{
            'head_sha':RUN_SHA,'status':'completed','conclusion':'success',
            'details_url':RUN_URL+'/job/987'}]}
        out=r38.assess(**x)
        self.assertTrue(out['source_binding']['pr_has_matching_run_check'])
        self.assertEqual(out['decision'],'HOLD_DEPLOYMENT_DIGEST_AND_OWNER_ACCEPTANCE_UNPROVEN')
        self.assertFalse(out['production_ready'])

    def test_check_url_substring_trick_cannot_prove_pr_ci(self):
        x=record();x['pr']['head']['sha']=RUN_SHA
        x['checks']={'total_count':1,'check_runs':[{
            'head_sha':RUN_SHA,'status':'completed','conclusion':'success',
            'details_url':'https://github.com.evil.invalid/'+RUN_URL}]}
        out=r38.assess(**x)
        self.assertFalse(out['source_binding']['pr_has_matching_run_check'])

    def test_deployment_record_appearing_is_not_deployed_digest(self):
        x=record();x['deployments']=[{'id':888,'sha':PR_SHA,'environment':'production'}]
        out=r38.assess(**x)
        self.assertEqual(out['stages']['deployment'],'GITHUB_DEPLOYMENT_RECORD_EXISTS_DIGEST_NOT_VERIFIED')
        self.assertFalse(out['deployment_digest_verified'])
        self.assertFalse(out['owner_acceptance_verified'])

    def test_deployment_page_limit_is_incomplete_coverage(self):
        x=record();x['deployments']=[{'id':i} for i in range(100)]
        out=r38.assess(**x)
        self.assertFalse(out['source_binding']['github_deployments_list_complete'])

    def test_malformed_source_pr_and_run_are_rejected(self):
        for kind,value in [('pr_draft',False),('pr_state','closed'),
                           ('pr_repo','another/account'),('run_event','push'),
                           ('run_repo_id',11),('run_path','evil.yml'),
                           ('run_conclusion','failure')]:
            x=record()
            if kind.startswith('pr_'):
                if kind=='pr_repo':x['pr']['head']['repo']['full_name']=value
                else:x['pr'][kind[3:]]=value
            else:
                if kind=='run_repo_id':x['run']['repository']['id']=value
                else:x['run'][kind[4:]]=value
            with self.subTest(kind=kind),self.assertRaises(r38.SourceNotVerified):r38.assess(**x)

    def test_modified_archive_sha_manifest_source_or_auth_flag_refused(self):
        for change in ('digest','source','authorized','filename'):
            x=record()
            if change=='digest':x['archive_sha']='0'*64
            if change=='source':x['manifest']['source_commit']='0'*40
            if change=='authorized':x['manifest']['production_ready']=True
            if change=='filename':x['manifest']['artifacts']['archive']['filename']='substitute.bin'
            with self.subTest(change=change),self.assertRaises(r38.SourceNotVerified):r38.assess(**x)

    def test_attestation_must_match_original_sha_signer_run_and_cryptographic_status(self):
        for key,value in [('verdict','BLOCKED'),('source_commit',PR_SHA),
                          ('verified_workflow_run_uri',RUN_URL+'/attempts/2'),
                          ('artifact_sha256','a'*64),('repository_id','9'),
                          ('signatures_cryptographically_verified_by_gh',False),
                          ('validated_certificate_source_identity',False),
                          ('trusted_timestamp_observed',False),('action_authorized',True)]:
            x=record();x['native'][key]=value
            with self.subTest(key=key):
                out=r38.assess(**x)
                self.assertFalse(out['signed_artifact']['cryptographic_provenance_verified_by_existing_rust'])
                self.assertIn('EXISTING_RUST_ATTESTATION_NOT_VERIFIED_FOR_EXACT_RUN',out['blockers'])

    def test_invalid_github_artifact_storage_provenance_never_promotes(self):
        for change in ('expired','wrong_source','missing_bundle','wrong_zip_digest'):
            x=record()
            if change=='expired':x['artifacts']['artifacts'][0]['expired']=True
            if change=='wrong_source':x['artifacts']['artifacts'][0]['workflow_run']['head_sha']=PR_SHA
            if change=='missing_bundle':x['artifacts']['artifacts'].pop()
            if change=='wrong_zip_digest':x['artifacts']['artifacts'][0]['digest']='not-sha256'
            out=r38.assess(**x)
            self.assertFalse(out['signed_artifact']['github_actions_storage_zip_metadata_available'])
            self.assertIn('GITHUB_RUN_ARTIFACT_STORAGE_PROVENANCE_INCOMPLETE',out['blockers'])

    def test_read_only_api_exact_allowlist_and_method(self):
        gh=Path('/fake/qualified-gh')
        with patch.object(r38,'command_json',return_value={'status':'public'}) as mocked:
            result=r38.gh_get(gh,f'repos/{r38.REPO}/pulls/{PR}',pr=PR,run_id=RUN)
            self.assertEqual(result,{'status':'public'})
            self.assertEqual(mocked.call_args.args[0][1:4],['api','-X','GET'])
        for bad in ('repos/'+r38.REPO+'/issues/10',
                    'repos/'+r38.REPO+'/actions/workflows/r29.yml/dispatches',
                    'repos/other/repo/pulls/10','repos/'+r38.REPO+'/releases'):
            with self.subTest(endpoint=bad),self.assertRaises(r38.SourceNotVerified):
                r38.gh_get(gh,bad,pr=PR,run_id=RUN)

    def test_json_cli_fail_closed_hides_stderr(self):
        fake=subprocess.CompletedProcess(['gh'],1,stdout='{"message":"denied"}',stderr='SECRET_TOKEN_123')
        with patch('subprocess.run',return_value=fake):
            with self.assertRaises(r38.SourceNotVerified) as context:
                r38.command_json(['gh','api','-X','GET','/repo'])
            self.assertNotIn('SECRET_TOKEN_123',str(context.exception))

    def test_pinned_binary_bytes_not_name_or_version_qualify(self):
        with tempfile.TemporaryDirectory() as tmp:
            ver=Path(tmp)/'verifier';gh=Path(tmp)/'gh'
            ver.write_bytes(b'known_verified_rust');gh.write_bytes(b'known_qualified_gh')
            ver.chmod(0o700);gh.chmod(0o700)
            with patch.object(r38,'EXISTING_RUST_VERIFIER_SHA256',sha256(ver.read_bytes()).hexdigest()),\
                 patch.object(r38,'EXISTING_QUALIFIED_GH_SHA256',sha256(gh.read_bytes()).hexdigest()):
                r38.pinned_executables(ver,gh)
                gh.write_bytes(b'tampered')
                with self.assertRaises(r38.SourceNotVerified):r38.pinned_executables(ver,gh)

    def test_executable_symlink_and_unbounded_file_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary=Path(tmp)/'bin';binary.write_bytes(b'bin')
            link=Path(tmp)/'link';link.symlink_to(binary)
            with self.assertRaises(r38.SourceNotVerified):r38.executable_sha256(link)
            with self.assertRaises(r38.SourceNotVerified):r38.bounded_file(binary,2)

    def test_native_verifier_invoked_with_exact_main_run_source_and_no_deploy(self):
        x=record()
        with patch.object(r38,'command_json',return_value=x['native']) as cmd:
            got=r38.native_verify(Path('/signed/rust-verifier'),Path('/qualified/gh'),
                                  Path('/local/original.tar.gz'),x['run'])
            self.assertEqual(got,x['native'])
            argv=cmd.call_args.args[0]
            self.assertEqual(argv[1],'verify-attestation')
            self.assertIn('--online',argv)
            self.assertIn('--source-commit',argv)
            self.assertEqual(argv[argv.index('--source-commit')+1],RUN_SHA)
            self.assertNotIn('--deploy',argv)
            self.assertEqual(cmd.call_args.kwargs['env']['PATH'].split(':')[0],'/qualified')

    def test_offline_synthetic_probe_reports_true_hold_without_gh(self):
        x=record()
        with tempfile.TemporaryDirectory() as tmp:
            archive=Path(tmp)/ARCHIVE;raw=b'synthetic fixture archive'
            archive.write_bytes(raw)
            x['archive_sha']=sha256(raw).hexdigest()
            x['manifest']['artifacts']['archive']['sha256']=x['archive_sha']
            x['native']['artifact_sha256']=x['archive_sha']
            manifest=Path(tmp)/'manifest.json';manifest.write_text(json.dumps(x['manifest']))
            def fake_api(gh,endpoint,*,pr,run_id,pr_sha=None):
                if '/pulls/' in endpoint:return x['pr']
                if '/artifacts?' in endpoint:return x['artifacts']
                if '/check-runs?' in endpoint:return x['checks']
                if '/deployments?' in endpoint:return x['deployments']
                if '/actions/runs/' in endpoint:return x['run']
                raise AssertionError('unexpected original endpoint')
            with patch.object(r38,'pinned_executables'),\
                 patch.object(r38,'gh_get',side_effect=fake_api),\
                 patch.object(r38,'native_verify',return_value=x['native']):
                result=r38.probe(gh=Path('/mock/gh'),verifier=Path('/mock/verifier'),
                                 artifact=archive,manifest_file=manifest,
                                 pr_number=PR,run_id=RUN)
                self.assertEqual(result['decision'],'HOLD_PR_TO_SIGNED_BUILD_SOURCE_MISMATCH')
                self.assertTrue(result['signed_artifact']['cryptographic_provenance_verified_by_existing_rust'])
                self.assertFalse(result['production_ready'])

    def test_output_exists_must_refuse_before_subprocess(self):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'existing';output.mkdir()
            with patch.object(r38,'probe',side_effect=AssertionError('probe must not be called')):
                with self.assertRaises(SystemExit):
                    r38.main(['--pr','10','--run-id',str(RUN),'--artifact','unused',
                              '--manifest','unused','--rust-verifier','unused',
                              '--qualified-gh','unused','--output-dir',str(output)])
            self.assertEqual(list(output.iterdir()),[])


if __name__=='__main__':unittest.main()
