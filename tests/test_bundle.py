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

from profiles import key_profile

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
        self.config = key_profile()
        self.config["ssh"].update({"host": "192.0.2.10", "fallback_hosts": ["192.0.2.11"], "port": 2222, "user": "bundle_test", "identity_file": None})
        self.config_path = self.directory / "services.json"
        self.config_path.write_text(json.dumps(self.config))
        self.args = bundle.parser().parse_args([
            "--legacy-ssh", "--source-only",
            "--config", str(self.config_path),
            "--public-key", str(self.key_dir / "client.pub"),
            "--host-key", str(self.key_dir / "host.pub"),
            "--output", str(self.directory / "client.zip"),
        ])
        self.operations = []
        self.commands = []
        self.receipt = {"user": "bundle_test", "created": True, "account": "created", "key": "added"}
        real_run = bundle.run
        def isolated_run(argv, **kwargs):
            command = [str(arg) for arg in argv]
            self.commands.append(command)
            server_path = str(ROOT / "server/sservcli_server.py")
            if server_path in command:
                operation = command[command.index(server_path) + 1]
                self.operations.append(operation)
                return json.dumps(self.receipt) if operation == "ensure" else "simulated account removal\n"
            return real_run(argv, **kwargs)
        self.runner = patch.object(bundle, "run", side_effect=isolated_run)
        self.runner.start()
        self.addCleanup(self.runner.stop)

    def test_bundle_runs_after_extraction_and_contains_settings_without_private_keys(self):
        output = bundle.package(self.args)
        self.assertEqual(self.operations, ["ensure"])
        with zipfile.ZipFile(output) as archive:
            profile = json.loads(archive.read("services.json"))
            self.assertEqual(profile["ssh"]["user"], "bundle_test")
            self.assertEqual(profile["ssh"]["fallback_hosts"], ["192.0.2.11"])
            self.assertEqual(profile["ssh"]["host"], "192.0.2.10")
            self.assertEqual(profile["ssh"]["port"], 2222)
            self.assertIsNone(profile["ssh"]["identity_file"])
            self.assertNotIn("known_hosts_file", profile["ssh"])
            self.assertIn("host_public_key", profile["ssh"])
            self.assertIn(b"sservcli.exe", archive.read("Start.cmd"))
            self.assertIn("Build.cmd", archive.namelist())
            self.assertIn(b"go build", archive.read("Build.cmd"))
            self.assertNotIn(b"cargo", archive.read("Build.cmd"))
            for name in ["client/go.mod", "client/cmd/sservcli/main.go", "client/internal/app/tunnel.go", "client/internal/app/daemon.go", "examples/services.token.windows.json"]:
                self.assertIn(name, archive.namelist())
            self.assertNotIn("sservcli.exe", archive.namelist())
            self.assertFalse(any(name.endswith(".py") for name in archive.namelist()))
            self.assertNotIn(".token", archive.namelist())
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
        result = subprocess.run(["go", "run", "./cmd/sservcli", "check", "--config", "../services.json"],
                                cwd=extracted / "client", capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_late_zip_publish_failure_removes_only_the_new_managed_account(self):
        with patch.object(bundle.os, "link", side_effect=OSError("fixture publish failure")):
            with self.assertRaisesRegex(OSError, "publish failure"):
                bundle.package(self.args)
        self.assertEqual(self.operations, ["ensure", "remove"])
        self.assertFalse(self.args.output.exists())

    def test_existing_output_is_preserved_and_new_archives_receive_a_suffix(self):
        self.args.output.write_text("existing download")
        output = bundle.package(self.args)
        self.assertEqual(self.args.output.read_text(), "existing download")
        self.assertEqual(output.name, "client-2.zip")
        with zipfile.ZipFile(output) as archive:
            self.assertIn("services.json", archive.namelist())
        self.receipt = {"user": "bundle_test", "created": False, "account": "reused", "key": "unchanged"}
        self.assertEqual(bundle.package(self.args).name, "client-3.zip")

    def test_invalid_profiles_are_rejected_before_provisioning(self):
        self.config["ssh"]["fallback_hosts"] = ["192.0.2.10"]
        self.config_path.write_text(json.dumps(self.config))
        with self.assertRaises(bundle.BundleError):
            bundle.package(self.args)
        self.assertEqual(self.operations, [])

    def test_existing_managed_account_reuses_it_and_passes_key_binding_to_helper(self):
        self.receipt = {"user": "bundle_test", "created": False, "account": "reused", "key": "added"}
        output = bundle.package(self.args)
        self.assertTrue(output.is_file())
        self.assertEqual(self.operations, ["ensure"])
        self.assertIn("--public-key", self.commands[0])
        self.assertIn(str(self.key_dir / "client.pub"), self.commands[0])

    def test_existing_external_account_still_produces_the_client_zip(self):
        self.receipt = {"user": "bundle_test", "created": False, "account": "external", "key": "unchanged"}
        self.assertTrue(bundle.package(self.args).is_file())
        self.assertEqual(self.operations, ["ensure"])

    def test_late_bundle_failure_never_removes_a_reused_or_external_account(self):
        for kind in ("reused", "external"):
            self.operations.clear()
            self.receipt = {"user": "bundle_test", "created": False, "account": kind, "key": "unchanged"}
            with self.subTest(kind=kind), patch.object(bundle.os, "link", side_effect=OSError("fixture publication failure")):
                with self.assertRaisesRegex(OSError, "publication failure"):
                    bundle.package(self.args)
            self.assertEqual(self.operations, ["ensure"])

    def test_inconsistent_account_receipt_never_triggers_automatic_deletion(self):
        self.receipt = {"user": "bundle_test", "created": True, "account": "reused", "key": "added"}
        with self.assertRaisesRegex(bundle.BundleError, "Invalid account setup receipt"):
            bundle.package(self.args)
        self.assertEqual(self.operations, ["ensure"])

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
        link = root / "client/internal/app/tunnel.go"
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


class TokenBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_keys = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp_keys.cleanup)
        cls.host = Path(cls.temp_keys.name) / "host"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(cls.host)], check=True)
        cls.public = cls.host.with_suffix(".pub").read_text().strip()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.config = json.loads((ROOT / "examples/services.token.json").read_text())
        self.config["ssh"].update(host="192.0.2.10", fallback_hosts=["192.0.2.11"])
        self.path = self.directory / "services.json"
        self.path.write_text(json.dumps(self.config))
        self.args = bundle.parser().parse_args(["--source-only", "--config", str(self.path), "--state-dir", str(self.directory / "state"),
                                              "--output", str(self.directory / "client.zip")])
        self.commands = []
        self.secret = "aB3dE5gH"
        self.args.token_file = self.directory / "current.token"
        self.args.token_file.write_text(self.secret)
        self.args.token_file.chmod(0o600)
        def native_prepare(argv, **kwargs):
            argv = [str(value) for value in argv]
            self.commands.append(argv)
            self.assertIn("token-prepare", argv)
            self.assertNotIn("--public-key", argv)
            return json.dumps({"user": "svc_tunnel_token1", "host_public_key": self.public, "token_active": True,
                               "token_sha256": hashlib.sha256(self.secret.encode()).hexdigest()})
        self.mock = patch.object(bundle, "run", side_effect=native_prepare)
        self.mock.start()
        self.addCleanup(self.mock.stop)

    def test_bundle_includes_current_token_with_system_sshd_identity_and_no_private_keys(self):
        from sservcli.token_auth import private_directory, read_private, write_private
        private_directory(self.args.state_dir)
        secret = "aB3dE5gH"
        write_private(self.args.state_dir / "access.token", secret + "\n")
        self.args.public_key = self.directory / "missing-client.pub"
        first = bundle.package(self.args)
        self.assertEqual(first.stat().st_mode & 0o777, 0o600)
        again = bundle.package(self.args)
        self.assertEqual(again.name, "client-2.zip")
        self.assertEqual(read_private(self.args.state_dir / "access.token").strip(), secret)
        with zipfile.ZipFile(first) as archive:
            profile = json.loads(archive.read("services.json"))
            self.assertEqual(profile["version"], 2)
            self.assertEqual(profile["ssh"]["user"], "svc_tunnel_token1")
            self.assertEqual(profile["ssh"]["port"], 22)
            self.assertEqual(profile["ssh"]["host_public_key"], self.public)
            self.assertEqual(profile["ssh"]["fallback_hosts"], ["192.0.2.11"])
            self.assertNotIn("identity_file", profile["ssh"])
            self.assertEqual(archive.read(".token"), (secret + "\n").encode())
            self.assertEqual((archive.getinfo(".token").external_attr >> 16) & 0o777, 0o600)
            self.assertIn("client/internal/app/tunnel.go", archive.namelist())
            self.assertNotIn("sservcli/token_tunnel.py", archive.namelist())
            self.assertFalse(any(name.endswith(".py") for name in archive.namelist()))
            self.assertIn(b"go build", archive.read("Build.cmd"))
            for name in archive.namelist():
                if name != ".token":
                    self.assertNotIn(secret.encode(), archive.read(name))
                self.assertNotIn(self.host.read_bytes(), archive.read(name))
                self.assertFalse(name.startswith(("var/", ".venv/")))

    def test_packaging_only_prepares_a_locked_account_without_issuing_a_token(self):
        bundle.package(self.args)
        self.assertEqual(len(self.commands), 1)
        self.assertFalse((self.args.state_dir / "access.token").exists())
        self.assertFalse((self.args.state_dir / "host_ed25519").exists())

    def test_legacy_input_retains_the_original_openssh_endpoint(self):
        legacy = key_profile()
        legacy["ssh"].update(host="192.0.2.10", port=2222)
        self.path.write_text(json.dumps(legacy))
        output = bundle.package(self.args)
        with zipfile.ZipFile(output) as archive:
            ssh = json.loads(archive.read("services.json"))["ssh"]
            self.assertEqual(ssh["port"], 2222)
            self.assertEqual(ssh["user"], "svc_tunnel_token1")
            self.assertNotIn("identity_file", ssh)

    def test_dry_run_does_not_change_accounts_or_issue_a_token(self):
        self.args.dry_run = True
        bundle.package(self.args)
        self.assertEqual(self.commands, [])
        self.assertFalse(self.args.state_dir.exists())
        self.assertFalse(self.args.output.exists())

    def test_stale_or_inactive_tokens_are_not_published(self):
        for active, digest in ((False, hashlib.sha256(self.secret.encode()).hexdigest()), (True, "0" * 64)):
            receipt = {"user": "svc_tunnel_token1", "host_public_key": self.public, "token_active": active, "token_sha256": digest}
            with self.subTest(active=active), patch.object(bundle, "run", return_value=json.dumps(receipt)):
                with self.assertRaisesRegex(bundle.BundleError, "matching active startup token"):
                    bundle.package(self.args)
            self.assertFalse(self.args.output.exists())

    def test_binary_bundle_contains_both_go_executables(self):
        self.args.source_only = False
        with patch.object(bundle, "build_client", return_value={"sservcli.exe": b"MZclient", "sservcli-askpass.exe": b"MZaskpass"}):
            output = bundle.package(self.args)
        with zipfile.ZipFile(output) as archive:
            self.assertEqual(archive.read("sservcli.exe"), b"MZclient")
            self.assertEqual(archive.read("sservcli-askpass.exe"), b"MZaskpass")
            self.assertEqual(archive.read(".token").strip(), self.secret.encode())

    def test_missing_token_stops_before_server_account_changes(self):
        self.args.token_file.unlink()
        with self.assertRaisesRegex(bundle.BundleError, "Cannot read current token"):
            bundle.package(self.args)
        self.assertEqual(self.commands, [])



if __name__ == "__main__":
    unittest.main()
