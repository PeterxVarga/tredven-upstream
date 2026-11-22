"""R8 offline/synthetic release-candidate integrity tests.

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
        archive_file.write_bytes(m.archive_bytes(b"forged-executable",self.args["license_bytes"],self.args["readme"]))
        manifest_file=self.dest/"manifest.json"
        manifest=json.loads(manifest_file.read_text())
        manifest["artifacts"]["archive"]["sha256"]=m.sha(archive_file.read_bytes())
        manifest_file.write_bytes(m.json_bytes(manifest))
        self.recompute_all_checksums()
        with self.assertRaisesRegex(m.InvalidCandidate,"CANDIDATE_BINARY_DIGEST_MISMATCH"):
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

if __name__=="__main__":
    unittest.main(verbosity=2)
