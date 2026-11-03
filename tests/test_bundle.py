import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("bundle", ROOT / "tools/bundle_windows.py")
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


def executable():
    value = bytearray(128)
    value[:2] = b"MZ"
    struct.pack_into("<I", value, 60, 64)
    value[64:68] = b"PE\0\0"
    struct.pack_into("<H", value, 68, 0x8664)
    struct.pack_into("<H", value, 88, 0x20b)
    return bytes(value)


class BundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.keys.cleanup)
        cls.key_dir = Path(cls.keys.name)
        for name in ("client", "host"):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(cls.key_dir / name)], check=True)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        native = self.directory / "native"
        native.mkdir()
        for name in ("sservcli.exe", "sservcli-desktop.exe"):
            (native / name).write_bytes(executable())
        validator = ROOT / "target/debug/sservcli"
        if not validator.is_file():
            self.skipTest("Run cargo build or make test to build the real profile validator")
        self.args = bundle.parser().parse_args([
            "--config", str(ROOT / "client/examples/services.json"),
            "--host", "192.0.2.10", "--fallback-hosts", '["192.0.2.11"]',
            "--user", "bundle_test", "--public-key", str(self.key_dir / "client.pub"),
            "--host-key", str(self.key_dir / "host.pub"),
            "--windows-artifact", str(native), "--validator", str(validator),
            "--output", str(self.directory / "client.zip"),
        ])
        self.operations = []
        real_run = bundle.run
        def isolated_run(argv, **kwargs):
            command = [str(arg) for arg in argv]
            server_path = str(ROOT / "server/sservcli_server.py")
            if server_path in command:
                operation = command[command.index(server_path) + 1]
                self.operations.append(operation)
                return "simulated account operation\n"
            return real_run(argv, **kwargs)
        self.runner = patch.object(bundle, "run", side_effect=isolated_run)
        self.runner.start()
        self.addCleanup(self.runner.stop)

    def test_bundle_has_executables_pinned_profile_and_no_private_keys(self):
        output = bundle.package(self.args)
        self.assertEqual(self.operations, ["install"])
        with zipfile.ZipFile(output) as archive:
            profile = json.loads(archive.read("services.json"))
            self.assertEqual(profile["ssh"]["user"], "bundle_test")
            self.assertEqual(profile["ssh"]["fallback_hosts"], ["192.0.2.11"])
            self.assertIsNone(profile["ssh"]["identity_file"])
            self.assertNotIn("known_hosts_file", profile["ssh"])
            self.assertIn("host_public_key", profile["ssh"])
            self.assertIn(b"--config", archive.read("Start.cmd"))
            self.assertIn("SHA256SUMS.txt", archive.namelist())
            for name in archive.namelist():
                self.assertNotIn(b"PRIVATE KEY", archive.read(name))
        bundle.run([self.args.validator, "check", "--config", self.write_profile(profile)])

    def write_profile(self, profile):
        path = self.directory / "extracted-profile.json"
        path.write_text(json.dumps(profile))
        return path

    def test_invalid_binary_stops_before_any_account_changes(self):
        (self.args.windows_artifact / "sservcli-desktop.exe").write_bytes(b"not an executable")
        with self.assertRaises(bundle.BundleError):
            bundle.package(self.args)
        self.assertEqual(self.operations, [])
        self.assertFalse(self.args.output.exists())

    def test_late_zip_publish_failure_removes_only_the_new_managed_account(self):
        with patch.object(bundle.os, "replace", side_effect=OSError("fixture publish failure")):
            with self.assertRaisesRegex(OSError, "publish failure"):
                bundle.package(self.args)
        self.assertEqual(self.operations, ["install", "remove"])
        self.assertFalse(self.args.output.exists())

    def test_existing_output_and_invalid_profiles_are_rejected_before_provisioning(self):
        self.args.output.write_text("existing download")
        with self.assertRaisesRegex(bundle.BundleError, "already exists"):
            bundle.package(self.args)
        self.assertEqual(self.args.output.read_text(), "existing download")
        self.args.output.unlink()
        self.args.fallback_hosts = '["192.0.2.10"]'
        with self.assertRaises(bundle.BundleError):
            bundle.package(self.args)
        self.assertEqual(self.operations, [])

    def test_dry_run_does_not_dispatch_ci_or_modify_accounts(self):
        self.args.dry_run = True
        self.args.windows_artifact = None
        with patch.object(bundle, "fetch_binaries") as fetch:
            bundle.package(self.args)
            fetch.assert_not_called()
        self.assertEqual(self.operations, [])
        self.assertFalse(self.args.output.exists())

    def test_zip_path_traversal_and_duplicate_executables_are_rejected(self):
        path = self.directory / "untrusted.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("../sservcli.exe", executable())
        with self.assertRaisesRegex(bundle.BundleError, "unsafe ZIP path"):
            bundle.read_binaries(path)
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("one/sservcli.exe", executable())
            archive.writestr("two/sservcli.exe", executable())
        with self.assertRaisesRegex(bundle.BundleError, "Duplicate"):
            bundle.read_binaries(path)

    def test_github_build_is_matched_to_its_request_and_source_commit(self):
        calls = []
        def gh(argv, **kwargs):
            argv = list(map(str, argv))
            calls.append(argv)
            if argv[:3] == ["git", "rev-parse", "HEAD"]:
                return "abc123\n"
            if argv[:2] == ["git", "status"]:
                return ""
            if argv[:2] == ["gh", "api"]:
                return '{"sha":"abc123"}'
            if argv[:3] == ["gh", "run", "list"]:
                return json.dumps([{"databaseId": 42, "displayTitle": "Windows binaries request", "headSha": "abc123"}])
            return ""
        with patch.object(bundle, "run", side_effect=gh), patch.object(bundle.shutil, "which", return_value="gh"), patch.object(bundle.uuid, "uuid4") as request:
            request.return_value.hex = "request"
            destination = self.directory / "download"
            self.assertEqual(bundle.fetch_binaries(destination, "owner/repo", "main"), destination)
        self.assertTrue(any(command[:3] == ["gh", "workflow", "run"] for command in calls))
        self.assertTrue(any(command[:4] == ["gh", "run", "watch", "42"] for command in calls))
        self.assertTrue(any(command[:4] == ["gh", "run", "download", "42"] for command in calls))


if __name__ == "__main__":
    unittest.main()
