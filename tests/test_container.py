"""Container bootstrap/lifetime tests; privileged account operations are mocked."""
import contextlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from server import container_runtime as container
from sservcli.config import ConfigError, token_profile, load_profile
from tools import bundle_windows

ROOT = Path(__file__).resolve().parents[1]


class ContainerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.env = {"CONFIG": str(self.directory / "services.json"), "SERVER_STATE": str(self.directory / "state"),
                    "SSHD_CONFIG": str(self.directory / "sshd_config"),
                    "SSHD_PID_FILE": str(self.directory / "run/sservcli/sshd.pid"),
                    "HOST_KEY_FILE": str(self.directory / "state/host.pub"),
                    "SSERVCLI_SSH_PORT": "2222", "SSERVCLI_LISTEN_ADDRESS": "127.0.0.1"}
        self.environment = patch.dict(os.environ, self.env, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.options = container.settings()
        profile = load_profile(ROOT / "examples/services.token.windows.json")
        profile["ssh"]["port"] = 21200
        self.options.config.write_text(json.dumps(profile))
        self.profile = token_profile(profile, self.options.port)

    def test_container_port_override_keeps_the_main_profile_unchanged(self):
        self.assertEqual(self.profile["ssh"]["port"], 2222)
        self.assertEqual(json.loads(self.options.config.read_text())["ssh"]["port"], 21200)
        for value in ("0", "65536", "2222\nPort 22", "２２２２"):
            with self.subTest(value=value), patch.dict(os.environ, {"SSERVCLI_SSH_PORT": value}):
                with self.assertRaises(ConfigError):
                    container.settings()
        with patch.dict(os.environ, {"SSERVCLI_LISTEN_ADDRESS": "0.0.0.0\nPermitOpen any"}):
            with self.assertRaises(ValueError):
                container.settings()

    def test_private_state_is_created_and_links_are_rejected(self):
        with patch.object(container.os, "chown") as owner:
            container.prepare_state(self.options.state)
        self.assertEqual(self.options.state.stat().st_mode & 0o777, 0o700)
        alias = self.directory / "linked_state"
        alias.symlink_to(self.options.state, target_is_directory=True)
        with patch.object(container.os, "chown") as owner, self.assertRaises(ConfigError):
            container.prepare_state(alias)
        owner.assert_not_called()

    def test_host_key_is_reused_and_its_public_half_is_repaired(self):
        self.options.state.mkdir(mode=0o700)
        # Keep the real key generation/derivation and private-file permissions;
        # root ownership alone is substituted in this unprivileged fixture.
        with (patch.object(container.provision, "safe_file", side_effect=lambda path: path.stat()),
              patch.object(container.provision.os, "fchown")):
            container.prepare_host_key(self.options.public_key)
            private = self.options.public_key.with_suffix("")
            original = private.read_bytes()
            public = self.options.public_key.read_bytes()
            self.options.public_key.write_text("stale public half\n")
            container.prepare_host_key(self.options.public_key)
        self.assertEqual(private.read_bytes(), original)
        self.assertEqual(self.options.public_key.read_bytes(), public)
        self.assertEqual(private.stat().st_mode & 0o777, 0o600)

    def test_bootstrap_locks_the_account_before_opening_ssh(self):
        fake = Mock()
        fake.resolve_token_user.return_value = "svc_tunnel"
        fake.ensure_token.return_value = {"uid": 12345}
        with (patch.object(container.provision, "Provisioner", return_value=fake),
              patch.object(container.provision, "management_lock", side_effect=contextlib.nullcontext),
              patch.object(container.provision, "atomic_write") as write):
            container.bootstrap(self.options, self.profile)
        fake.ensure_token.assert_called_once_with("svc_tunnel", [f"127.0.0.1:{s['remote_port']}" for s in self.profile["services"]], activate=False)
        fake.lock_token.assert_called_once_with("svc_tunnel", 12345)
        self.assertEqual(write.call_args.args[1], "Port 2222\nListenAddress 127.0.0.1\n")
        self.assertTrue((self.directory / "run/sshd").is_dir())

    def test_health_requires_all_supervised_processes_and_the_matching_port(self):
        self.options.ready_file.parent.mkdir(parents=True)
        info = {"sshd_pid": os.getpid(), "controller_pid": os.getpid(), "helper_pid": os.getpid(), "port": 2222}
        self.options.ready_file.write_text(json.dumps(info))
        self.assertTrue(container.healthcheck(self.options))
        for field, value in (("helper_pid", 1), ("port", 21200)):
            self.options.ready_file.write_text(json.dumps({**info, field: value}))
            self.assertFalse(container.healthcheck(self.options))
        self.options.ready_file.unlink()
        self.assertFalse(container.healthcheck(self.options))

    def test_failed_sshd_start_aborts_instead_of_issuing_a_token(self):
        process = Mock()
        process.poll.return_value = 255
        with self.assertRaisesRegex(ConfigError, "sshd exited"):
            container.wait_for_daemon(process, Mock(), __import__("threading").Event())

    def test_shutdown_terminates_only_the_supervised_daemon_group(self):
        process = Mock(pid=12345)
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("sshd", 5), 0]
        with patch.object(container.os, "killpg") as kill:
            container.stop_daemon(process)
        self.assertEqual([call.args for call in kill.call_args_list], [(12345, signal.SIGTERM), (12345, signal.SIGKILL)])

    def test_supervisor_revokes_the_token_before_stopping_sshd_even_on_start_failure(self):
        real_is_file = Path.is_file
        for fail in (False, True):
            order = []
            controller = Mock(user="svc_tunnel")
            controller.process.pid = 23456
            controller.close.side_effect = lambda: order.append("token-revoked")
            if fail:
                controller.start.side_effect = ConfigError("fixture token activation failure")
            master = Mock(pid=12345)
            manager = Mock(sshd="/usr/sbin/sshd")
            stopping = Mock()
            stopping.is_set.return_value = False
            stopping.wait.return_value = True
            with (self.subTest(fail=fail),
                  patch.object(container.os, "geteuid", return_value=0),
                  patch.object(Path, "is_file", lambda path: str(path) == "/.dockerenv" or real_is_file(path)),
                  patch.object(container, "prepare_state"),
                  patch.object(container, "prepare_host_key"),
                  patch.object(container, "FileLock", side_effect=lambda path: contextlib.nullcontext()),
                  patch.object(container.threading, "Event", return_value=stopping),
                  patch.object(container.signal, "signal"),
                  patch.object(container, "bootstrap", return_value=manager),
                  patch.object(container.subprocess, "Popen", return_value=master),
                  patch.object(container, "wait_for_daemon", return_value=True),
                  patch.object(container, "TokenServer", return_value=controller) as start,
                  patch.object(container, "write_private") as write,
                  patch.object(container, "stop_daemon", side_effect=lambda process: order.append("sshd-stopped"))):
                if fail:
                    with self.assertRaisesRegex(ConfigError, "activation failure"):
                        container.serve()
                    write.assert_not_called()
                else:
                    self.assertEqual(container.serve(), 0)
                    self.assertEqual(json.loads(write.call_args.args[1])["port"], 2222)
                self.assertEqual(start.call_args.args[0]["ssh"]["port"], 2222)
                self.assertEqual(order, ["token-revoked", "sshd-stopped"])

    def test_bundle_uses_container_identity_and_returns_download_to_the_host_user(self):
        output = self.directory / "client.zip"
        output.write_bytes(b"fixture")
        with (patch.dict(os.environ, {"BUNDLE_UID": "1001", "BUNDLE_GID": "1002"}),
              patch.object(container, "healthcheck", return_value=True),
              patch.object(bundle_windows, "package", return_value=output) as package,
              patch.object(container.os, "chown") as owner):
            container.bundle([])
        args = package.call_args.args[0]
        self.assertEqual(args.token_port, 2222)
        self.assertEqual(args.config, self.options.config)
        self.assertEqual(args.host_key, self.options.public_key)
        self.assertEqual(args.sshd_pid_file, str(self.options.pid_file))
        self.assertEqual(args.output, Path("/dist/sservcli-windows-token.zip"))
        owner.assert_called_once_with(output, 1001, 1002)

    def test_bundle_refuses_a_stopped_server_or_invalid_host_owner(self):
        with patch.object(container, "healthcheck", return_value=False), patch.object(bundle_windows, "package") as package:
            with self.assertRaisesRegex(ConfigError, "healthy"):
                container.bundle([])
        package.assert_not_called()
        with (patch.dict(os.environ, {"BUNDLE_UID": "-1", "BUNDLE_GID": "1001"}),
              patch.object(container, "healthcheck", return_value=True),
              patch.object(bundle_windows, "package") as package):
            with self.assertRaisesRegex(ConfigError, "numeric host IDs"):
                container.bundle([])
        package.assert_not_called()


if __name__ == "__main__":
    unittest.main()
