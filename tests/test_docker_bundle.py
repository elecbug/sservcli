"""Docker controller/ZIP flow over real Unix IPC, without host account changes."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import patch
import zipfile

from test_host_bridge import BridgeFixture
from server import container_server
from sservcli.config import ConfigError, load_profile
from sservcli.token_auth import read_private, write_private
from tools import bundle_windows as bundle
from tools import docker_compose

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_FILES = {"sservcli.exe", "sservcli-askpass.exe", "services.json", ".token",
                 "Start.cmd", "Stop.cmd", "README.txt", "SHA256SUMS.txt"}


class DockerServerTests(BridgeFixture):
    def setUp(self):
        super().setUp()
        self.state = self.directory / "state"
        self.controller = container_server.Controller(self.profile, self.state, self.socket)
        self.addCleanup(self.controller.close)
        self.output = self.directory / "client.zip"

    def start(self):
        return self.controller.start()

    def package(self, source=False):
        environment = {"BUNDLE_UID": str(os.getuid()), "BUNDLE_GID": str(os.getgid()),
                       "BUNDLE_OUTPUT": str(self.output), "BUILD_CLIENT": "0" if source else "1"}
        with (patch.dict(os.environ, environment, clear=True),
              patch.object(bundle, "build_client", return_value={"sservcli.exe": b"MZclient", "sservcli-askpass.exe": b"MZaskpass"}),
              patch.object(bundle, "server_command", side_effect=AssertionError("The container cannot provision host accounts directly")),
              patch.object(container_server.os, "chown") as owner):
            output = container_server.package(self.config, self.state, self.socket)
        owner.assert_called_once_with(output, os.getuid(), os.getgid())
        return output

    def test_container_lifetime_controls_existing_host_ssh(self):
        self.start()
        container_server.healthcheck(self.profile, self.state, self.socket)
        token = read_private(self.state / "access.token").strip()
        self.assertEqual(token, "Ab1Cd2E3")
        self.assertEqual((self.state / "access.token").stat().st_mode & 0o777, 0o600)
        metadata = read_private(self.state / "server.json")
        self.assertNotIn(token, metadata)
        self.assertEqual(json.loads(metadata)["ssh_port"], 21200)
        self.controller.close()
        self.wait_revoked()
        self.assertFalse((self.state / "ready.json").exists())
        with self.assertRaises(OSError):
            container_server.healthcheck(self.profile, self.state, self.socket)

    def test_windows_zip_includes_current_token_existing_port_and_host_key(self):
        self.start()
        output = self.package()
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.operations, ["token-serve", "token-prepare"])
        self.assertEqual(load_profile(self.config), self.profile)
        with zipfile.ZipFile(output) as archive:
            self.assertEqual(set(archive.namelist()), RUNTIME_FILES)
            ssh = json.loads(archive.read("services.json"))["ssh"]
            self.assertEqual(ssh["port"], 21200)
            self.assertEqual(ssh["user"], "svc_tunnel_token1")
            self.assertEqual(ssh["host_public_key"], self.controller.lease.receipt["host_public_key"])
            self.assertEqual(archive.read(".token").strip(), read_private(self.state / "access.token").strip().encode())
            self.assertEqual((archive.getinfo(".token").external_attr >> 16) & 0o777, 0o600)
            for line in archive.read("SHA256SUMS.txt").decode().splitlines():
                digest, name = line.split("  ", 1)
                self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(), digest)

    def test_source_only_still_includes_the_active_token(self):
        self.start()
        with zipfile.ZipFile(self.package(source=True)) as archive:
            self.assertIn("client/go.mod", archive.namelist())
            self.assertIn("Build.cmd", archive.namelist())
            self.assertNotIn("sservcli.exe", archive.namelist())
            self.assertEqual(archive.read(".token").strip(), b"Ab1Cd2E3")
            self.assertEqual(json.loads(archive.read("services.json"))["ssh"]["port"], 21200)

    def test_an_old_health_record_does_not_claim_an_active_server(self):
        self.start()
        ready = json.loads(read_private(self.state / "ready.json"))
        ready["lease_id"] = "previous-lease"
        write_private(self.state / "ready.json", json.dumps(ready))
        with self.assertRaisesRegex(ConfigError, "no longer owns"):
            self.package()
        self.assertFalse(self.output.exists())

    def test_stale_token_is_rejected_before_publication(self):
        self.start()
        write_private(self.state / "access.token", "BadToken\n")
        with self.assertRaisesRegex(ConfigError, "matching active startup token"):
            self.package()
        self.assertFalse(self.output.exists())

    def test_local_write_failure_revokes_the_host_lease(self):
        with patch.object(container_server, "write_private", side_effect=OSError("fixture disk failure")):
            with self.assertRaisesRegex(OSError, "fixture disk"):
                self.start()
        self.wait_revoked()
        self.assertIsNone(self.controller.lock)
        self.assertFalse((self.state / "ready.json").exists())

    def test_another_controller_cannot_remove_the_live_readiness_record(self):
        self.start()
        other = container_server.Controller(self.profile, self.state, self.socket)
        with self.assertRaisesRegex(ConfigError, "already in use"):
            other.start()
        other.close()
        container_server.healthcheck(self.profile, self.state, self.socket)
        self.controller.lease.heartbeat()


class ComposeRoleTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("docker"), "Docker CLI required for Compose validation")
    def test_custom_profile_and_build_options_survive_sudo_environment_filtering(self):
        original = subprocess.run
        expected = "/tmp/custom profile/office's services.json"
        results, temporary_paths = [], []
        def sudo_docker(command, **kwargs):
            self.assertEqual(command[:2], ["sudo", "docker"])
            path = Path(command[command.index("--env-file") + 1])
            temporary_paths.append(path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            self.assertNotIn("TOKEN", path.read_text())
            # Simulate sudo removing the public interpolation variables.
            environment = {key: value for key, value in kwargs["env"].items()
                           if key not in ("CONFIG", "BUILD_CLIENT", "WINDOWS_ARCH", "SSERVCLI_BUNDLE_NAME")}
            result = original(command[1:], cwd=kwargs["cwd"], env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            results.append(json.loads(result.stdout)["services"]["server"])
            return result
        with (patch.dict(os.environ, {"CONFIG": expected, "WINDOWS_ARCH": "arm64", "BUILD_CLIENT": "0"}),
              patch.object(docker_compose.subprocess, "run", side_effect=sudo_docker)):
            self.assertEqual(docker_compose.run("sudo docker", ["config", "--format", "json"]), 0)
        service = results[0]
        profile = next(mount for mount in service["volumes"] if mount["target"] == "/config/services.json")
        self.assertEqual(profile["source"], expected)
        self.assertEqual(service["build"]["args"]["WINDOWS_ARCH"], "arm64")
        self.assertEqual(service["build"]["args"]["BUILD_CLIENT"], "0")
        self.assertTrue(all(not path.exists() for path in temporary_paths))

    @unittest.skipUnless(shutil.which("docker"), "Docker CLI required for Compose validation")
    def test_docker_runs_the_controller_with_only_a_fixed_host_ssh_socket(self):
        result = subprocess.run(["docker", "compose", "config", "--format", "json"],
                                cwd=ROOT, capture_output=True, text=True, check=True)
        services = json.loads(result.stdout)["services"]
        self.assertEqual(set(services), {"server"})
        service = services["server"]
        self.assertEqual(service["network_mode"], "none")
        self.assertTrue(service["read_only"])
        self.assertEqual(service["restart"], "unless-stopped")
        self.assertIn("healthcheck", service)
        self.assertNotIn("ports", service)
        self.assertNotIn("pid", service)
        self.assertFalse(service.get("privileged", False))
        mounts = {mount["target"]: mount for mount in service["volumes"]}
        self.assertEqual(set(mounts), {"/config/services.json", "/host-ssh", "/state", "/dist"})
        self.assertTrue(mounts["/config/services.json"]["read_only"])
        self.assertTrue(mounts["/host-ssh"]["read_only"])
        self.assertEqual(mounts["/host-ssh"]["source"], "/var/lib/sservcli/ssh-bridge/ipc")
        self.assertNotIn("HOST_KEY_FILE", service["environment"])
        self.assertNotIn("SSHD_CONFIG", service["environment"])
        for mount in mounts.values():
            self.assertNotIn(mount["source"], ("/etc/ssh", "/etc", "/var/run/docker.sock"))


if __name__ == "__main__":
    unittest.main()
