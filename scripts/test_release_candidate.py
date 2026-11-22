"""R8/R12 offline/synthetic release-candidate integrity and license annex tests.

No GitHub, crates.io, Podman, deployment, publish or private application.
"""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

CODE=Path(__file__).with_name("release_candidate.py")
SPEC=importlib.util.spec_from_file_location("r8_local_release",CODE)
m=importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(m)

class ReleaseCandidateTests(unittest.TestCase):
    def setUp(self):
        self.work=tempfile.TemporaryDirectory(prefix="tredven-r8-synthetic-")
        self.addCleanup(self.work.cleanup)
        self.root=Path(self.work.name)
        self.dest=self.root/"candidate"
        self.args=dict(
            binary=b"\x7fELFsynthetic-not-an-executable",
            crate=b"synthetic-source-crate-not-real",
            license_bytes=b"synthetic MIT license\n",
            readme=b"synthetic readme\n",
            notices=b"synthetic third-party license notices\n",
            source_commit="a"*40,
            version="0.1.0",
            target="x86_64-unknown-linux-gnu",
            rustc="rustc 1.100.0 (test fixture)",
            cargo="cargo 1.100.0 (test fixture)")
        m.write_candidate(self.dest,**self.args)

    def test_valid_checksums_are_only_local_unattested(self):
        report=m.verify_candidate(self.dest)
        self.assertEqual(report["status"],"LOCAL_RC_UNATTESTED_NO_RELEASE")
        self.assertFalse(report["signature_verified"])
        self.assertFalse(report["publication_authorized"])
        self.assertFalse(report["production_ready"])

    def test_byte_identical_inputs_produce_same_archive_and_checksums(self):
        second=self.root/"candidate2"
        m.write_candidate(second,**self.args)
        names=[p.name for p in self.dest.iterdir()]
        self.assertEqual(sorted(names),sorted(p.name for p in second.iterdir()))
        for name in names:
            self.assertEqual((self.dest/name).read_bytes(),(second/name).read_bytes(),name)

    def test_mutated_archive_is_blocked(self):
        p=next(self.dest.glob("*.tar.gz"))
        p.write_bytes(p.read_bytes()+b"tamper")
        with self.assertRaisesRegex(m.InvalidCandidate,"CHECKSUM_MISMATCH"):
            m.verify_candidate(self.dest)

    def test_mutated_source_crate_is_blocked(self):
        p=next(self.dest.glob("*.crate"))
        p.write_bytes(p.read_bytes()+b"tamper")
        with self.assertRaisesRegex(m.InvalidCandidate,"CHECKSUM_MISMATCH"):
            m.verify_candidate(self.dest)

    def test_extra_file_cannot_join_release(self):
        (self.dest/"untracked-private.txt").write_text("never ship\n")
        with self.assertRaisesRegex(m.InvalidCandidate,"UNEXPECTED_FILES"):
            m.verify_candidate(self.dest)

    def test_modified_manifest_cannot_grant_publication(self):
        p=self.dest/"manifest.json"
        report=json.loads(p.read_text())
        report["publication_authorized"]=True
        p.write_bytes(m.json_bytes(report))
        with self.assertRaisesRegex(m.InvalidCandidate,"SCHEMA_OR_AUTHORITY_INVALID"):
            m.verify_candidate(self.dest)

    def test_replaced_checksum_is_rejected(self):
        p=self.dest/"SHA256SUMS"
        p.write_text("0"*64+"  manifest.json\n")
        with self.assertRaisesRegex(m.InvalidCandidate,"FILE_SCOPE_INVALID"):
            m.verify_candidate(self.dest)

    def test_rehashed_unsafe_tar_member_is_still_rejected(self):
        import io
        import tarfile
        archive_file=next(self.dest.glob("*.tar.gz"))
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode="w:gz") as tar:
            data=b"not-an-authorized-package-member"
            item=tarfile.TarInfo("../../unwanted")
            item.size=len(data)
            tar.addfile(item,io.BytesIO(data))
        archive_file.write_bytes(stream.getvalue())
        manifest_file=self.dest/"manifest.json"
        manifest=json.loads(manifest_file.read_text())
        manifest["artifacts"]["archive"]["sha256"]=m.sha(archive_file.read_bytes())
        manifest_file.write_bytes(m.json_bytes(manifest))
        self.recompute_all_checksums()
        with self.assertRaisesRegex(m.InvalidCandidate,"UNEXPECTED_ARCHIVE_FILE_SCOPE"):
            m.verify_candidate(self.dest)

    def test_rehashed_changed_binary_cannot_avoid_original_binary_hash(self):
        archive_file=next(self.dest.glob("*.tar.gz"))
        archive_file.write_bytes(m.archive_bytes(b"forged-executable",self.args["license_bytes"],self.args["readme"],self.args["notices"]))
        manifest_file=self.dest/"manifest.json"
        manifest=json.loads(manifest_file.read_text())
        manifest["artifacts"]["archive"]["sha256"]=m.sha(archive_file.read_bytes())
        manifest_file.write_bytes(m.json_bytes(manifest))
        self.recompute_all_checksums()
        with self.assertRaisesRegex(m.InvalidCandidate,"CANDIDATE_BINARY_DIGEST_MISMATCH"):
            m.verify_candidate(self.dest)

    def test_archive_contains_license_annex(self):
        import io
        import tarfile
        archive_file=next(self.dest.glob("*.tar.gz"))
        with tarfile.open(fileobj=io.BytesIO(archive_file.read_bytes()),mode="r:gz") as tar:
            self.assertEqual(tar.extractfile("THIRD_PARTY_NOTICES.txt").read(),self.args["notices"])

    def test_missing_license_annex_is_blocked_even_if_rehashed(self):
        import io
        import tarfile
        archive_file=next(self.dest.glob("*.tar.gz"))
        buf=io.BytesIO()
        with tarfile.open(fileobj=buf,mode="w:gz") as output:
            with tarfile.open(archive_file,mode="r:gz") as original:
                for member in original:
                    if member.name!="THIRD_PARTY_NOTICES.txt":
                        output.addfile(member,original.extractfile(member))
        archive_file.write_bytes(buf.getvalue())
        manifest_file=self.dest/"manifest.json"
        manifest=json.loads(manifest_file.read_text())
        manifest["artifacts"]["archive"]["sha256"]=m.sha(archive_file.read_bytes())
        manifest_file.write_bytes(m.json_bytes(manifest))
        self.recompute_all_checksums()
        with self.assertRaisesRegex(m.InvalidCandidate,"UNEXPECTED_ARCHIVE_FILE_SCOPE"):
            m.verify_candidate(self.dest)

    def test_changed_notices_blocked_even_with_rehashed_archive(self):
        archive_file=next(self.dest.glob("*.tar.gz"))
        archive_file.write_bytes(m.archive_bytes(
            self.args["binary"],self.args["license_bytes"],self.args["readme"],
            b"unexpected legal notices"))
        manifest_file=self.dest/"manifest.json"
        manifest=json.loads(manifest_file.read_text())
        manifest["artifacts"]["archive"]["sha256"]=m.sha(archive_file.read_bytes())
        manifest_file.write_bytes(m.json_bytes(manifest))
        self.recompute_all_checksums()
        with self.assertRaisesRegex(m.InvalidCandidate,"CANDIDATE_LICENSE_NOTICES_DIGEST_MISMATCH"):
            m.verify_candidate(self.dest)

    def recompute_all_checksums(self):
        files=[p for p in self.dest.iterdir() if p.name!="SHA256SUMS"]
        sums="".join(f"{m.sha(p.read_bytes())}  {p.name}\n" for p in sorted(files))
        (self.dest/"SHA256SUMS").write_text(sums)

    def test_file_symlinks_are_not_followed(self):
        p=self.dest/"manifest.json"
        backup=self.root/"manifest-backup.json"
        shutil.move(p,backup)
        p.symlink_to(backup)
        with self.assertRaisesRegex(m.InvalidCandidate,"NON_SYMLINK_FILE"):
            m.verify_candidate(self.dest)

    def test_symlinked_candidate_directory_rejected(self):
        linked=self.root/"alias"
        linked.symlink_to(self.dest, target_is_directory=True)
        with self.assertRaisesRegex(m.InvalidCandidate,"NORMAL_CANDIDATE_DIRECTORY"):
            m.verify_candidate(linked)

    def test_cli_reports_unattested_and_exit_zero_only_for_local_byte_verification(self):
        result=subprocess.run([sys.executable,"-I","-B",str(CODE),
            "verify","--dir",str(self.dest)],capture_output=True,text=True,check=False)
        self.assertEqual(result.returncode,0,result.stderr)
        receipt=json.loads(result.stdout)
        self.assertEqual(receipt["result"],"LOCAL_RC_VERIFIED_UNATTESTED_NO_RELEASE")
        self.assertIs(receipt["signature_verified"],False)
        self.assertIs(receipt["production_ready"],False)

    def test_invalid_candidate_exit_two(self):
        (self.dest/"SHA256SUMS").write_text("corrupt\n")
        result=subprocess.run([sys.executable,"-I","-B",str(CODE),
            "verify","--dir",str(self.dest)],capture_output=True,text=True,check=False)
        self.assertEqual(result.returncode,2)
        self.assertIn("BLOCKED_LOCAL_RELEASE_CANDIDATE",result.stderr)

class LicenseAnnexTests(unittest.TestCase):
    def setUp(self):
        from unittest import mock
        from types import SimpleNamespace
        self.mock=mock
        self.ns=SimpleNamespace
        self.work=tempfile.TemporaryDirectory(prefix="tredven-r12-licenses-")
        self.addCleanup(self.work.cleanup)
        self.root=Path(self.work.name)
        self.repo=self.root/"repo"
        self.repo.mkdir()
        self.crate=self.root/"registry"/"src"/"index"/"fixture-1.2.3"
        self.crate.mkdir(parents=True)
        (self.crate/"Cargo.toml").write_text('[package]\nname = "fixture"\n')
        (self.crate/"LICENSE-MIT").write_text("Copyright 2026 Test Holder\n")
        (self.crate/"LICENSE-UNICODE").write_text("Unicode test condition\n")
        self.source="registry+https://github.com/rust-lang/crates.io-index"
        (self.repo/"Cargo.lock").write_text(
            'version = 4\n[[package]]\nname = "fixture"\n'
            'version = "1.2.3"\nsource = "'+self.source+'"\n')
        self.package=dict(name="fixture",version="1.2.3",source=self.source,
                          manifest_path=str(self.crate/"Cargo.toml"),
                          license="MIT AND Unicode-3.0",license_file=None)
        self.env={"CARGO_HOME":str(self.root)}

    def _build(self,packages):
        result=self.ns(stdout=json.dumps({"packages":packages}))
        with self.mock.patch.object(m.subprocess,"run",return_value=result) as runner:
            output=m.build_third_party_notices(self.repo,self.env)
            self.assertIn("--offline",runner.call_args.args[0])
            self.assertIn("--locked",runner.call_args.args[0])
            return output

    def test_keeps_complete_license_text_without_license_guessing(self):
        text=self._build([self.package]).decode()
        self.assertIn("MIT AND Unicode-3.0",text)
        self.assertIn("Copyright 2026 Test Holder",text)
        self.assertIn("Unicode test condition",text)
        self.assertIn("Registry packages: 1",text)
        self.assertIn(m.sha((self.repo/"Cargo.lock").read_bytes()),text)

    def test_fails_closed_without_original_license_files(self):
        (self.crate/"LICENSE-MIT").unlink()
        (self.crate/"LICENSE-UNICODE").unlink()
        with self.assertRaisesRegex(m.InvalidCandidate,"UPSTREAM_LICENSE_TEXT_MISSING"):
            self._build([self.package])

    def test_fails_closed_on_incomplete_metadata(self):
        with self.assertRaisesRegex(m.InvalidCandidate,"CARGO_METADATA_LOCKED_CRATES_MISMATCH"):
            self._build([])

    def test_does_not_read_license_outside_registry(self):
        outside=self.root/"untrusted"/"fixture-1.2.3"
        outside.mkdir(parents=True)
        (outside/"LICENSE-MIT").write_text("do-not-read\n")
        (outside/"Cargo.toml").write_text("")
        forged={**self.package,"manifest_path":str(outside/"Cargo.toml")}
        with self.assertRaisesRegex(m.InvalidCandidate,"UNTRUSTED_UPSTREAM_LICENSE_PATH"):
            self._build([forged])


class PortableMuslNoticeTests(unittest.TestCase):
    """R19 musl archiving stays opt-in, bounded and license-notice complete."""
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="r19-portable-musl-")
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.dest=self.root/"musl-candidate"
        self.runtime_notices=b"<html><body>Rust std and musl libc license notices</body></html>"
        self.kw=dict(binary=b"synthetic-static-pie-not-executable",
                     crate=b"synthetic-crate",license_bytes=b"synthetic MIT",
                     readme=b"synthetic README",notices=b"synthetic crates notices",
                     source_commit="a"*40, version="0.1.0",
                     target="x86_64-unknown-linux-musl",
                     rustc="rustc 1.100.0 (fixture)",cargo="cargo 1.100.0 (fixture)",
                     runtime_notices=self.runtime_notices)

    def test_musl_build_archive_contains_pinned_rust_standard_library_notices(self):
        m.write_candidate(self.dest,**self.kw)
        receipt=m.verify_candidate(self.dest)
        self.assertEqual(receipt["target"],"x86_64-unknown-linux-musl")
        self.assertFalse(receipt["publication_authorized"])
        self.assertEqual(receipt["artifacts"]["rust_runtime_notices_in_archive_sha256"],
                         m.sha(self.runtime_notices))
        import tarfile
        with tarfile.open(next(self.dest.glob("*.tar.gz")),"r:gz") as tar:
            names=set(tar.getnames())
            self.assertEqual(names,{"bin/tredven-upstream","LICENSE","README.md",
                                    "THIRD_PARTY_NOTICES.txt","RUST_RUNTIME_NOTICES.html"})
            self.assertEqual(tar.extractfile("RUST_RUNTIME_NOTICES.html").read(),
                             self.runtime_notices)

    def test_musl_candidate_without_runtime_notices_fails_before_creation(self):
        args={**self.kw,"runtime_notices":None}
        with self.assertRaisesRegex(m.InvalidCandidate,"MUSL_RUST_RUNTIME_LICENSE_NOTICES_REQUIRED"):
            m.write_candidate(self.dest,**args)
        self.assertFalse(self.dest.exists())

    def test_gnu_candidate_must_not_silently_claim_musl_notice_coverage(self):
        args={**self.kw,"target":"x86_64-unknown-linux-gnu"}
        with self.assertRaisesRegex(m.InvalidCandidate,"RUST_RUNTIME_NOTICES_ONLY_QUALIFIED_FOR_MUSL"):
            m.write_candidate(self.dest,**args)

    def test_tampered_notices_fail_even_when_archive_and_checksums_rehashed(self):
        m.write_candidate(self.dest,**self.kw)
        archive=next(self.dest.glob("*.tar.gz"))
        archive.write_bytes(m.archive_bytes(self.kw["binary"],self.kw["license_bytes"],
                                           self.kw["readme"],self.kw["notices"],
                                           b"<html>musl libc MODIFIED</html>"))
        manifest=self.dest/"manifest.json"
        data=json.loads(manifest.read_text())
        data["artifacts"]["archive"]["sha256"]=m.sha(archive.read_bytes())
        manifest.write_bytes(m.json_bytes(data))
        files=[f for f in self.dest.iterdir() if f.name!="SHA256SUMS"]
        (self.dest/"SHA256SUMS").write_text(
            "".join(f"{m.sha(f.read_bytes())}  {f.name}\n" for f in sorted(files)))
        with self.assertRaisesRegex(m.InvalidCandidate,
                                    "CANDIDATE_RUST_RUNTIME_NOTICES_DIGEST_MISMATCH"):
            m.verify_candidate(self.dest)


if __name__=="__main__":
    unittest.main(verbosity=2)
