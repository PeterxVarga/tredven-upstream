"""R28 isolated migration test-driver guardrails. All tests are offline; no Podman calls."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("r28_disposable_postgres_upgrade.py")
SPEC = importlib.util.spec_from_file_location("tredven_r28_disposable_postgres", SCRIPT)
r28 = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(r28)


class R28IsolatedUpgradeTests(unittest.TestCase):
    def test_readiness_waits_for_tcp_not_entrypoint_temporary_unix_socket(self):
        calls = []
        def fake_podman(*args, **kwargs):
            calls.append(args)
            self.assertIn("-h", args)
            self.assertEqual(args[args.index("-h") + 1], "127.0.0.1")
            return subprocess.CompletedProcess(args, 0, b"accepting connections", b"")
        with patch.object(r28, "podman", side_effect=fake_podman):
            r28.wait_ready("tredven-r28-isolated-test")
        self.assertEqual(len(calls), 1)

    def test_preflight_never_allows_root(self):
        with patch.object(r28.os, "geteuid", return_value=0), patch.object(
            r28, "podman"
        ) as subprocess_not_allowed:
            with self.assertRaisesRegex(RuntimeError, "DO_NOT_RUN_AS_ROOT"):
                r28.preflight()
            subprocess_not_allowed.assert_not_called()

    def test_preflight_fails_closed_when_cached_images_unavailable(self):
        def fake_podman(*args, **kwargs):
            if args[0] == "info":
                return subprocess.CompletedProcess(args, 0, b"true\n", b"")
            if args[:2] == ("image", "exists"):
                return subprocess.CompletedProcess(args, 1, b"", b"")
            self.fail("Unexpected Podman operation: " + repr(args))
        with patch.object(r28.os, "geteuid", return_value=1000), patch.object(
            r28, "podman", side_effect=fake_podman
        ):
            with self.assertRaisesRegex(RuntimeError, "REQUIRED_CACHED_IMAGE_UNAVAILABLE"):
                r28.preflight()

    def test_synthetic_compose_fixture_changes_only_db_image_with_pinned_git_tags(self):
        with tempfile.TemporaryDirectory(prefix="r28-git-unit-") as parent:
            source,old,new=r28.source_fixture(Path(parent))
            self.assertEqual(len(old),40)
            self.assertEqual(len(new),40)
            self.assertNotEqual(old,new)
            self.assertEqual(r28.git(source,"show","r28-16:compose.yaml"),r28.COMPOSE16.rstrip())
            self.assertEqual(r28.git(source,"show","r28-17:compose.yaml"),r28.COMPOSE17.rstrip())
            self.assertEqual(len(r28.CHECKS),8)
            self.assertEqual(set(r28.CHECKS), {
                ("db","health"),("db","integration"),("db","data-migration"),
                ("db","rollback"),("api","health"),("api","integration"),
                ("worker","health"),("worker","integration")
            })

    def test_cleanup_names_are_explicit_never_global_prune_or_live_volume(self):
        with tempfile.TemporaryDirectory(prefix="r28-cleanup-unit-") as parent:
            resources=r28.Isolated(Path(parent))
            resources.containers=[resources.db16, resources.db17]
            resources.volumes=[resources.vol16, resources.vol17]
            calls=[]
            def fake_podman(*args,**kwargs):
                calls.append(args)
                # Simulate successful removal and absence.
                return subprocess.CompletedProcess(args,1 if args[1]=="exists" else 0,b"",b"")
            with patch.object(r28,"podman",side_effect=fake_podman):
                resources.cleanup()
            self.assertEqual(len(calls),8)
            self.assertTrue(all(
                args[0] in ("rm","volume","container") for args in calls
            ))
            self.assertFalse(any("prune" in args for args in calls))
            self.assertTrue(all(
                any(value.startswith(r28.PREFIX) for value in args)
                for args in calls
            ))


if __name__ == "__main__":
    unittest.main()
