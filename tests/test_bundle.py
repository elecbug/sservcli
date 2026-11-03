import importlib.util
import json
from pathlib import Path
import hashlib
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("bundle", ROOT / "tools/bundle_windows.py")
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


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
        self.config = json.loads((ROOT / "client/examples/services.json").read_text())
        self.config["ssh"].update({"host": "192.0.2.10", "fallback_hosts": ["192.0.2.11"], "port": 2222, "user": "bundle_test", "identity_file": None})
        self.config_path = self.directory / "services.json"
        self.config_path.write_text(json.dumps(self.config))
        self.args = bundle.parser().parse_args([
            "--config", str(self.config_path),
            "--public-key", str(self.key_dir / "client.pub"),
            "--host-key", str(self.key_dir / "host.pub"),
            "--output", str(self.directory / "client.zip"),
        ])
        self.operations = []
        self.commands = []
        real_run = bundle.run
        def isolated_run(argv, **kwargs):
            command = [str(arg) for arg in argv]
            self.commands.append(command)
            server_path = str(ROOT / "server/sservcli_server.py")
            if server_path in command:
                operation = command[command.index(server_path) + 1]
                self.operations.append(operation)
                return "simulated account operation\n"
            return real_run(argv, **kwargs)
        self.runner = patch.object(bundle, "run", side_effect=isolated_run)
        self.runner.start()
        self.addCleanup(self.runner.stop)

    def test_bundle_runs_after_extraction_and_contains_settings_without_private_keys(self):
        output = bundle.package(self.args)
        self.assertEqual(self.operations, ["install"])
        with zipfile.ZipFile(output) as archive:
            profile = json.loads(archive.read("services.json"))
            self.assertEqual(profile["ssh"]["user"], "bundle_test")
            self.assertEqual(profile["ssh"]["fallback_hosts"], ["192.0.2.11"])
            self.assertEqual(profile["ssh"]["host"], "192.0.2.10")
            self.assertEqual(profile["ssh"]["port"], 2222)
            self.assertIsNone(profile["ssh"]["identity_file"])
            self.assertNotIn("known_hosts_file", profile["ssh"])
            self.assertIn("host_public_key", profile["ssh"])
            self.assertIn(b"--config", archive.read("Start.cmd"))
            self.assertIn("Build.cmd", archive.namelist())
            self.assertIn(b"sservcli.windows_launcher --check", archive.read("Build.cmd"))
            self.assertNotIn(b"cargo", archive.read("Build.cmd"))
            for name in ["sservcli/__main__.py", "sservcli/config.py", "sservcli/tunnel.py", "sservcli/desktop.py", "sservcli/windows.py", "client/examples/services.windows.json"]:
                self.assertIn(name, archive.namelist())
            self.assertNotIn("sservcli-desktop.exe", archive.namelist())
            self.assertIn("SHA256SUMS.txt", archive.namelist())
            for name in archive.namelist():
                self.assertNotIn((self.key_dir / "client").read_bytes(), archive.read(name))
                self.assertFalse(any(part in ("target", "node_modules", ".git", "gen", "key") for part in Path(name).parts))
        self.assertFalse(any(Path(command[0]).name in ("gh", "git", "cargo", "npm", "npm.cmd") for command in self.commands))
        bundle.validate_profile(profile)
        extracted = self.directory / "extracted"
        with zipfile.ZipFile(output) as archive:
            archive.extractall(extracted)
            sums = archive.read("SHA256SUMS.txt").decode().splitlines()
            for line in sums:
                expected, name = line.split("  ", 1)
                self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(), expected)
        result = subprocess.run([sys.executable, "-m", "sservcli", "check", "--config", "services.json"],
                                cwd=extracted, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_late_zip_publish_failure_removes_only_the_new_managed_account(self):
        with patch.object(bundle.os, "link", side_effect=OSError("fixture publish failure")):
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
        self.config["ssh"]["fallback_hosts"] = ["192.0.2.10"]
        self.config_path.write_text(json.dumps(self.config))
        with self.assertRaises(bundle.BundleError):
            bundle.package(self.args)
        self.assertEqual(self.operations, [])

    def test_dry_run_never_builds_dispatches_or_modifies_accounts(self):
        self.args.dry_run = True
        bundle.package(self.args)
        self.assertEqual(self.operations, [])
        self.assertEqual(self.commands, [])
        self.assertFalse(self.args.output.exists())

    def test_source_allowlist_excludes_caches_keys_and_rejects_links(self):
        root = self.directory / "source"
        for name, data in bundle.source_files().items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        for name in ("key/secret.pem", ".git/config", "sservcli/__pycache__/cache.py", "sservcli/private.pem", "target/generated.rs"):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"do not distribute")
        files = bundle.source_files(root)
        self.assertFalse(any(b"do not distribute" in data for data in files.values()))
        link = root / "sservcli/tunnel.py"
        link.unlink()
        link.symlink_to(self.key_dir / "client")
        with self.assertRaisesRegex(bundle.BundleError, "linked"):
            bundle.source_files(root)

    def test_existing_identity_is_read_from_config(self):
        self.config["ssh"]["identity_file"] = "~/.ssh/my_existing_key"
        self.config_path.write_text(json.dumps(self.config))
        output = bundle.package(self.args)
        with zipfile.ZipFile(output) as archive:
            self.assertEqual(json.loads(archive.read("services.json"))["ssh"]["identity_file"], "~/.ssh/my_existing_key")

    def test_client_only_packages_existing_profile_without_public_key_or_account_changes(self):
        self.args.client_only = True
        self.args.public_key = None
        output = bundle.package(self.args)
        self.assertEqual(self.operations, [])
        self.assertEqual(self.commands, [])
        with zipfile.ZipFile(output) as archive:
            self.assertEqual(json.loads(archive.read("services.json")), self.config)
            self.assertIn("Start.cmd", archive.namelist())

    def test_validation_rejects_invalid_types_fields_and_service_settings(self):
        for mutation in range(7):
            config = json.loads(json.dumps(self.config))
            if mutation == 0: config["ssh"]["port"] = True
            elif mutation == 1: config["services"][1]["local_port"] = config["services"][0]["local_port"]
            elif mutation == 2: config["services"][0]["remote_host"] = "0.0.0.0"
            elif mutation == 3: config["services"][0]["launch"] = ["tool", "{unknown}"]
            elif mutation == 4: config["services"][0]["path"] = "//example.com"
            elif mutation == 5: config["reconnect"]["enabled"] = "yes"
            else: config["ssh"]["typo"] = "ignored"
            with self.subTest(mutation=mutation), self.assertRaises(bundle.BundleError):
                bundle.validate_profile(config)


if __name__ == "__main__":
    unittest.main()
