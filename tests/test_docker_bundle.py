"""Host SSH preparation and network-free Docker packaging; no privileged mutations."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from tools import bundle_windows as bundle
from tools import container_bundle as consumer
from tools import docker_bundle as producer

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_FILES = {"sservcli.exe", "sservcli-askpass.exe", "services.json", ".token",
                 "Start.cmd", "Stop.cmd", "README.txt", "SHA256SUMS.txt"}


class DockerBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.profile = json.loads((ROOT / "examples/services.token.windows.json").read_text())
        self.profile["ssh"].update(host="192.0.2.10", port=21200)
        self.config = self.directory / "services.json"
        self.config.write_text(json.dumps(self.profile))
        self.token = self.directory / "access.token"
        self.secret = "Ab1Cd2E3"
        self.token.write_text(self.secret + "\n")
        self.token.chmod(0o600)
        self.key = "ssh-ed25519 " + "A" * 32
        self.output = self.directory / "downloads/client.zip"
        self.args = bundle.parser().parse_args(["--config", str(self.config), "--token-file", str(self.token),
                                               "--output", str(self.output)])
        self.args.docker = "sudo docker"
        self.receipt = {"user": "svc_tunnel_token1", "host_public_key": self.key, "token_active": True,
                        "token_sha256": hashlib.sha256(self.secret.encode()).hexdigest()}
        self.docker_calls = []
        self.host_calls = []
        self.staged = []

    def host_prepare(self, command):
        self.host_calls.append([str(value) for value in command])
        self.assertIn("token-prepare", self.host_calls[-1])
        self.assertNotIn(self.secret, str(command))
        return json.dumps(self.receipt)

    def docker_run(self, command, *, cwd, env, check):
        self.docker_calls.append(list(command))
        self.assertEqual(command[:5], ["sudo", "docker", "compose", "--profile", "tools"])
        self.assertNotIn(self.secret, str(command))
        self.assertTrue(check)
        self.assertEqual(env["BUILD_CLIENT"], "0" if self.args.source_only else "1")
        if "run" not in command:
            return subprocess.CompletedProcess(command, 0)
        directory = Path(env["SSERVCLI_BUNDLE_INPUT"])
        self.staged.append(directory)
        self.assertEqual(set(p.name for p in directory.iterdir()), {"services.json", ".token"})
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual((directory / ".token").stat().st_mode & 0o777, 0o600)
        config = json.loads((directory / "services.json").read_text())
        self.assertEqual(config["ssh"]["port"], 21200)
        self.assertEqual(config["ssh"]["host_public_key"], self.key)
        self.assertEqual(config["ssh"]["user"], "svc_tunnel_token1")
        environment = {"BUNDLE_INPUT": str(directory), "BUNDLE_OUTPUT": str(self.output),
                       "BUNDLE_UID": env["SSERVCLI_BUNDLE_UID"], "BUNDLE_GID": env["SSERVCLI_BUNDLE_GID"],
                       "BUILD_CLIENT": env["BUILD_CLIENT"], "WINDOWS_ARCH": env["WINDOWS_ARCH"]}
        # Execute the real container-side packager locally, substituting only
        # prebuilt EXEs and ownership. Any attempted SSH provisioning is a bug.
        with (patch.dict(os.environ, environment, clear=True),
              patch.object(bundle, "server_command", side_effect=AssertionError("Host SSH operations cannot run in the builder")),
              patch.object(bundle, "build_client", return_value={"sservcli.exe": b"MZclient", "sservcli-askpass.exe": b"MZaskpass"}),
              patch.object(consumer.os, "chown") as owner):
            consumer.package()
        owner.assert_called_once_with(self.output, os.getuid(), os.getgid())
        return subprocess.CompletedProcess(command, 0)

    def run_pipeline(self):
        with (patch.object(producer, "ROOT", self.directory),
              patch.object(producer.subprocess, "run", side_effect=self.docker_run),
              patch.object(bundle, "run", side_effect=self.host_prepare)):
            return producer.package(self.args)

    def test_host_port_key_and_active_token_survive_a_minimal_docker_zip(self):
        self.run_pipeline()
        self.assertEqual(len(self.host_calls), 1)
        self.assertEqual(len(self.docker_calls), 2)
        self.assertIn("build", self.docker_calls[0])
        self.assertIn("run", self.docker_calls[1])
        self.assertTrue(all(not directory.exists() for directory in self.staged))
        self.assertEqual(json.loads(self.config.read_text()), self.profile)
        self.assertEqual(self.token.read_text(), self.secret + "\n")
        with zipfile.ZipFile(self.output) as archive:
            self.assertEqual(set(archive.namelist()), RUNTIME_FILES)
            config = json.loads(archive.read("services.json"))
            self.assertEqual(config["ssh"]["port"], 21200)
            self.assertEqual(config["ssh"]["host_public_key"], self.key)
            self.assertEqual(archive.read(".token").strip(), self.secret.encode())
            for line in archive.read("SHA256SUMS.txt").decode().splitlines():
                digest, name = line.split("  ", 1)
                self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(), digest)

    def test_inactive_host_token_never_reaches_the_packaging_container(self):
        self.receipt["token_active"] = False
        with self.assertRaisesRegex(bundle.BundleError, "matching active startup token"):
            self.run_pipeline()
        self.assertEqual(len(self.docker_calls), 1)
        self.assertFalse(self.output.exists())
        self.assertEqual(list((self.directory / "var").iterdir()), [])

    def test_explicit_source_only_download_preserves_host_connection_settings(self):
        self.args.source_only = True
        self.run_pipeline()
        with zipfile.ZipFile(self.output) as archive:
            self.assertIn("client/go.mod", archive.namelist())
            self.assertIn("Build.cmd", archive.namelist())
            self.assertNotIn("sservcli.exe", archive.namelist())
            self.assertEqual(archive.read(".token").strip(), self.secret.encode())
            self.assertEqual(json.loads(archive.read("services.json"))["ssh"]["port"], 21200)

    def test_missing_token_fails_before_any_docker_or_host_setup(self):
        self.token.unlink()
        with self.assertRaisesRegex(bundle.BundleError, "Cannot read current token"):
            self.run_pipeline()
        self.assertEqual(self.docker_calls, [])
        self.assertEqual(self.host_calls, [])

    def test_dry_run_needs_no_token_docker_or_sudo(self):
        self.args.dry_run = True
        self.token.unlink()
        self.run_pipeline()
        self.assertEqual(self.docker_calls, [])
        self.assertEqual(self.host_calls, [])
        self.assertFalse(self.output.exists())

    def test_consumer_requires_a_pinned_host_profile_and_valid_owner(self):
        source = self.directory / "input"
        source.mkdir()
        (source / "services.json").write_text(json.dumps(self.profile))
        (source / ".token").write_text(self.secret)
        env = {"BUNDLE_INPUT": str(source), "BUNDLE_UID": str(os.getuid()), "BUNDLE_GID": str(os.getgid())}
        with patch.dict(os.environ, env, clear=True), self.assertRaisesRegex(bundle.BundleError, "pinned SSH host key"):
            consumer.package()
        env["BUNDLE_UID"] = "-1"
        with patch.dict(os.environ, env, clear=True), self.assertRaisesRegex(bundle.BundleError, "host user"):
            consumer.package()

    def test_consumer_rejects_linked_input_instead_of_reading_host_state(self):
        source = self.directory / "input"
        source.mkdir()
        (source / "services.json").symlink_to(self.config)
        with self.assertRaisesRegex(bundle.BundleError, "Invalid staged input"):
            consumer.read_input(source / "services.json", 1024 * 1024)


class ComposeRoleTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("docker"), "Docker CLI required for Compose validation")
    def test_compose_exposes_only_an_offline_builder_and_staged_inputs(self):
        result = subprocess.run(["docker", "compose", "--profile", "tools", "config", "--format", "json"],
                                cwd=ROOT, capture_output=True, text=True, check=True)
        services = json.loads(result.stdout)["services"]
        self.assertEqual(set(services), {"builder"})
        service = services["builder"]
        self.assertEqual(service["network_mode"], "none")
        self.assertTrue(service["read_only"])
        self.assertNotIn("ports", service)
        self.assertNotIn("healthcheck", service)
        self.assertNotIn("pid", service)
        self.assertFalse(service.get("privileged", False))
        mounts = {mount["target"]: mount for mount in service["volumes"]}
        self.assertEqual(set(mounts), {"/input", "/output"})
        self.assertTrue(mounts["/input"]["read_only"])
        self.assertNotIn("HOST_KEY_FILE", service["environment"])
        self.assertNotIn("SSHD_CONFIG", service["environment"])


if __name__ == "__main__":
    unittest.main()
