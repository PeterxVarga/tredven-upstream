#!/usr/bin/env python3
"""Offline/unit-only R20 policy tests; synthetic gh outputs are NOT signatures."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import release_candidate as rc
from scripts import verify_signed_alpha as sig


class R20AttestationPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='tredven-r20-verify-unit-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.directory = self.root / 'candidate'
        self.fake_gh = self.root / 'fake-gh'
        self.fake_gh.write_bytes(b'fixture: no actual cryptography')
        self.kw = dict(
            binary=b'UNIT_FIXTURE_BINARY', crate=b'UNIT_FIXTURE_CRATE',
            license_bytes=b'UNIT_FIXTURE_LICENSE',readme=b'UNIT_FIXTURE_README',
            notices=b'UNIT_FIXTURE_CRATE_NOTICES',
            runtime_notices=b'<html>Rust std and musl libc UNIT LICENSE fixture</html>',
            source_commit='a'*40, version='0.1.0',
            target='x86_64-unknown-linux-musl',
            rustc='rustc 1.100.0 unit',cargo='cargo 1.100.0 unit')
        rc.write_candidate(self.directory,**self.kw)

    def _fake_verifier(self, command, timeout=60):
        if command[0] == str(self.fake_gh):
            if command[1:] == ['--version']:
                return b'gh version 2.105.0 (UNIT TEST ONLY)\n'
            if command[1:3] == ['attestation','verify']:
                raise sig.Blocked('SYNTHETIC_NO_SIGNED_ATTESTATION')
            self.fail('Unexpected gh command')
        return self.real_run(command,timeout)

    def test_no_sigstore_record_always_blocks(self):
        self.real_run=sig.run_checked
        with mock.patch.object(sig,'run_checked',side_effect=self._fake_verifier):
            with self.assertRaisesRegex(sig.Blocked,'SYNTHETIC_NO_SIGNED_ATTESTATION'):
                sig.verify(self.directory,None,str(self.fake_gh))

    def test_empty_verified_result_is_not_claimed_as_success(self):
        self.real_run=sig.run_checked
        def simulate(cmd,timeout=60):
            if cmd[:3]==[str(self.fake_gh),'attestation','verify']:
                return b'[]'
            if cmd==[str(self.fake_gh),'--version']:
                return b'gh version 2.105.0 (UNIT TEST ONLY)\n'
            return self.real_run(cmd,timeout)
        with mock.patch.object(sig,'run_checked',side_effect=simulate):
            with self.assertRaisesRegex(sig.Blocked,'NO_VERIFIED_GITHUB_ATTESTATION'):
                sig.verify(self.directory,None,str(self.fake_gh))

    def test_policy_flags_exact_with_only_simulated_gh_result(self):
        self.real_run=sig.run_checked
        calls=[]
        def simulate(cmd,timeout=60):
            if cmd[:3]==[str(self.fake_gh),'attestation','verify']:
                calls.append(cmd)
                return b'[{}]'  # SIMULATED: never a real signature verification
            if cmd==[str(self.fake_gh),'--version']:
                return b'gh version 2.105.0 (UNIT TEST ONLY)\n'
            return self.real_run(cmd,timeout)
        with mock.patch.object(sig,'run_checked',side_effect=simulate):
            report=sig.verify(self.directory,None,str(self.fake_gh))
        self.assertEqual(report['result'],'GITHUB_SIGNED_ARCHIVE_VERIFIED_NOT_A_RELEASE_GRANT')
        self.assertFalse(report['release_authorized'])
        self.assertFalse(report['production_ready'])
        self.assertEqual(len(calls),1)
        cmd=calls[0]
        self.assertIn('--deny-self-hosted-runners',cmd)
        for flag,value in [('--repo',sig.REPO),('--signer-workflow',sig.SIGNER),
                           ('--source-ref',sig.REF),('--source-digest','a'*40)]:
            i=cmd.index(flag)
            self.assertEqual(cmd[i+1],value)

    def test_invalid_local_candidate_does_not_invoke_gh(self):
        target=next(self.directory.glob('*.tar.gz'))
        target.write_bytes(b'INTENTIONALLY_CORRUPTED')
        with mock.patch.object(sig,'run_checked',wraps=sig.run_checked) as calls:
            with self.assertRaises(sig.Blocked):
                sig.verify(self.directory,None,str(self.fake_gh))
            self.assertTrue(all(cmd[0][0] != str(self.fake_gh) for cmd in calls.call_args_list))

    def test_gnu_candidate_not_accepted_as_portable_signed_alpha(self):
        different=self.root/'gnu'
        rc.write_candidate(different,**{**self.kw,'target':'x86_64-unknown-linux-gnu',
                                   'runtime_notices':None})
        with self.assertRaisesRegex(sig.Blocked,'UNEXPECTED_CANDIDATE_SOURCE_OR_AUTHORITY'):
            sig.verify(different,None,str(self.fake_gh))

    def test_bundle_symlink_not_passed_to_gh(self):
        source=self.root/'raw-bundle'
        source.write_bytes(b'synthetic attestation not a signature')
        link=self.root/'bundle-alias'
        link.symlink_to(source)
        self.real_run=sig.run_checked
        def simulate(cmd,timeout=60):
            if cmd==[str(self.fake_gh),'--version']:
                return b'gh version 2.105.0 (UNIT TEST ONLY)\n'
            if cmd[:3]==[str(self.fake_gh),'attestation','verify']:
                self.fail('gh must not be called with a symlinked bundle')
            return self.real_run(cmd,timeout)
        with mock.patch.object(sig,'run_checked',side_effect=simulate):
            with self.assertRaisesRegex(sig.Blocked,'FILE_IS_MISSING_SYMLINK_OR_OUT_OF_BOUNDS'):
                sig.verify(self.directory,link,str(self.fake_gh))


class ManualWorkflowStaticPolicyTests(unittest.TestCase):
    def setUp(self):
        self.txt=(Path(__file__).resolve().parents[1]/'.github/workflows/r20-manual-alpha-provenance.yml').read_text()

    def check(self,s: str) -> None:
        import re
        self.assertRegex(s,r'(?m)^on:\s*\n  workflow_dispatch:\s*\n')
        self.assertNotRegex(s,r'(?m)^  (push|pull_request|schedule|release|workflow_run):')
        for identity in [
            "github.repository == 'PeterxVarga/tredven-upstream'",
            'github.repository_id == 1467524521',
            "github.ref == 'refs/heads/main'",
            "github.event_name == 'workflow_dispatch'",
            "github.actor == 'PeterxVarga'",
            "github.triggering_actor == 'PeterxVarga'",
        ]:
            self.assertIn(identity,s)
        for pin in [
            'actions/checkout@11d5960a326750d5838078e36cf38b85af677262',
            'actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8',
            'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02',
        ]:
            self.assertIn(pin,s)
        for must in ['--portable-musl','--dir "$GITHUB_WORKSPACE/output/r20-alpha"',
                     'sha256sum --check SHA256SUMS',
                     'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
                     'subject-path: ${{ github.workspace }}/output/r20-alpha/tredven-upstream-v0.1.0-x86_64-unknown-linux-musl.tar.gz',
                     'r20-alpha-candidate-bytes','r20-alpha-attestation-bundle',
                     'retention-days: 7','publication_authorized',
                     'RUST_RUNTIME_NOTICES.html']:
            self.assertIn(must,s)
        # No releases, repository mutation, external messages or credentials in shell commands.
        for line in s.splitlines():
            stripped=line.strip()
            self.assertFalse(stripped.startswith(('gh release ', 'git push ',
                                                 'kubectl ', 'ssh ', 'curl -X POST')),line)

    def test_owner_only_dispatch_exact_attested_archive_and_no_publish(self):
        self.check(self.txt)

    def test_removing_owner_gate_is_detected(self):
        with self.assertRaises(AssertionError):
            self.check(self.txt.replace("github.actor == 'PeterxVarga' &&",'',1))

    def test_removing_attestor_sha_is_detected(self):
        with self.assertRaises(AssertionError):
            self.check(self.txt.replace('4d101475d8b20a2381f78447822ac1eab6504dd8','v4'))

    def test_adding_automatic_push_event_is_detected(self):
        with self.assertRaises(AssertionError):
            self.check(self.txt.replace('  workflow_dispatch:', '  push:\n  workflow_dispatch:',1))


if __name__ == '__main__':
    unittest.main()
