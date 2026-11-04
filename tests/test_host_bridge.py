"""Real Unix IPC and child lifetime; all privileged operations use a fake helper."""
import hashlib
import contextlib
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from server import ssh_bridge
from sservcli.config import ConfigError, load_profile
from sservcli.host_bridge import Lease, connect, request, response, scope

ROOT = Path(__file__).resolve().parents[1]
FAKE_HELPER = r'''
import hashlib, json, pathlib, signal, sys
operation, directory, reusing = sys.argv[1:]
directory = pathlib.Path(directory)
profile = json.loads((directory / "profile.json").read_text())
receipt = {"user": "svc_tunnel_token1", "requested_user": profile["ssh"]["user"],
           "host_public_key": "ssh-ed25519 " + "A" * 32,
           "permitted": ["127.0.0.1:" + str(s["remote_port"]) for s in profile["services"]]}
active = directory / "active"
saved = directory / "issued.token"
previous = saved.read_text() if saved.exists() else None
token = previous or "Ab1Cd2E3"
if operation == "token-serve":
    if reusing == "1":
        token = json.loads(sys.stdin.readline())["token"]
        if token != previous:
            raise SystemExit("Saved token does not match fixture account")
    else:
        if reusing == "missing" and previous:
            raise SystemExit("Saved token is missing for the fixture account")
        token = "Z9y8X7w6" if previous == "Ab1Cd2E3" else "Ab1Cd2E3"
    saved.write_text(token)
    saved.chmod(0o600)
    active.write_text("yes")
    receipt.update(token=token, token_reused=reusing == "1")
    def stop(*_):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop)
    try:
        print(json.dumps(receipt), flush=True)
        sys.stdin.read()
    finally:
        active.unlink(missing_ok=True)
        (directory / "revoked").write_text("yes")
else:
    receipt.update(token_active=active.exists(), token_sha256=hashlib.sha256(token.encode()).hexdigest())
    print(json.dumps(receipt), flush=True)
'''


class BridgeFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sservcli-ipc-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.profile = load_profile(ROOT / "examples/services.token.windows.json")
        self.profile["ssh"].update(host="192.0.2.10", port=21200)
        self.config = self.directory / "profile.json"
        self.config.write_text(json.dumps(self.profile))
        self.operations = []
        def factory(operation, reuse_token=None, *, no_reset_token=False):
            self.operations.append(operation)
            mode = "1" if reuse_token else "missing" if no_reset_token else "0"
            return subprocess.Popen([sys.executable, "-c", FAKE_HELPER, operation, str(self.directory), mode],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.socket = self.directory / "bridge.sock"
        self.server = ssh_bridge.BridgeServer(self.socket, {"profile": self.profile}, self.directory, factory=factory)
        self.worker = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01})
        self.worker.start()
        self.addCleanup(self.close_server)

    def close_server(self):
        self.server.shutdown()
        self.server.close_clients()
        self.server.server_close()
        self.worker.join(timeout=5)
        self.assertFalse(self.worker.is_alive())

    def lease(self):
        lease = Lease(self.socket, self.profile).start()
        self.addCleanup(lease.close)
        return lease

    def wait_revoked(self):
        deadline = time.monotonic() + 3
        while self.server.active_id is not None and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertIsNone(self.server.active_id)
        self.assertTrue((self.directory / "revoked").exists())
        self.assertFalse((self.directory / "active").exists())


class HostBridgeTests(BridgeFixture):
    def test_release_revokes_before_ack_and_uses_existing_host_port(self):
        lease = self.lease()
        lease.heartbeat()
        self.assertEqual(request(self.socket, "ping", self.profile)["ssh_port"], 21200)
        receipt = request(self.socket, "prepare", self.profile)["receipt"]
        self.assertTrue(receipt["token_active"])
        self.assertEqual(receipt["token_sha256"], hashlib.sha256(lease.receipt["token"].encode()).hexdigest())
        self.assertNotIn("token", receipt)
        lease.close()
        self.wait_revoked()

    def test_controller_crash_revokes_the_host_account(self):
        lease = self.lease()
        peer, lease.peer = lease.peer, None
        peer.close()  # abrupt controller EOF, without a release message
        self.wait_revoked()

    def test_unresponsive_controller_loses_its_lease(self):
        self.server.request_timeout = 0.15
        self.lease()
        self.wait_revoked()

    def test_another_controller_cannot_rotate_the_current_token(self):
        first = self.lease()
        with self.assertRaisesRegex(ConfigError, "already owns"):
            Lease(self.socket, self.profile).start()
        first.heartbeat()
        self.assertEqual(self.operations, ["token-serve"])

    def test_unapproved_account_ports_and_commands_never_start_a_helper(self):
        for field, value in (("user", "root"), ("ssh_port", 22), ("destinations", ["127.0.0.1:1"])):
            with self.subTest(field=field):
                peer = connect(self.socket)
                modified = scope(self.profile)
                modified[field] = value
                try:
                    peer.send({"operation": "lease", "scope": modified})
                    with self.assertRaisesRegex(ConfigError, "approved host profile"):
                        response(peer)
                finally:
                    peer.close()
        with self.assertRaisesRegex(ConfigError, "Unsupported"):
            request(self.socket, "run arbitrary command", self.profile)
        self.assertEqual(self.operations, [])

    def test_forced_helper_exit_is_detected_by_heartbeat(self):
        lease = self.lease()
        with self.server.lock:
            child = next(iter(self.server.children))
        child.terminate()
        child.wait(timeout=3)
        with self.assertRaisesRegex(ConfigError, "lease ended"):
            lease.heartbeat()
        self.wait_revoked()

    def test_host_helper_shutdown_revokes_its_container_lease(self):
        self.lease()
        self.server.close_clients()
        self.wait_revoked()

    def test_token_reuse_never_places_the_credential_in_helper_arguments(self):
        self.server.factory = None
        self.server.snapshot.update(sshd_config="/etc/ssh/sshd_config", ssh_service="ssh",
                                    host_key="/etc/ssh/ssh_host_ed25519_key.pub")
        with patch.object(ssh_bridge.subprocess, "Popen") as start:
            self.server.helper("token-serve", "Ab1Cd2E3")
        command = start.call_args.args[0]
        self.assertIn("--reuse-token-stdin", command)
        self.assertNotIn("Ab1Cd2E3", str(command))

    def test_reuse_requests_cannot_extend_the_approved_scope(self):
        peer = connect(self.socket)
        try:
            different = scope(self.profile)
            different["destinations"] = ["127.0.0.1:1"]
            peer.send({"operation": "lease", "scope": different, "reuse_token": "Ab1Cd2E3"})
            with self.assertRaisesRegex(ConfigError, "approved host profile"):
                response(peer)
        finally:
            peer.close()
        self.assertEqual(self.operations, [])


class InstallTests(unittest.TestCase):
    def test_systemd_runs_an_approved_root_owned_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "host-state"
            config = Path(temporary) / "services.json"
            profile = load_profile(ROOT / "examples/services.token.json")
            profile["ssh"]["port"] = 21200
            config.write_text(json.dumps(profile))
            writes = {}
            def write(path, text, *, mode=0o600):
                writes[path] = text
                if str(path).startswith(str(state)):
                    path.write_text(text)
                    path.chmod(mode)
            def directory(path):
                path.mkdir(mode=0o700, parents=True, exist_ok=True)
            with (patch.object(ssh_bridge, "STATE", state), patch.object(ssh_bridge, "SOCKET_DIR", state / "ipc"),
                  patch.object(ssh_bridge.provision, "atomic_write", side_effect=write),
                  patch.object(ssh_bridge.provision, "ensure_state_dir", side_effect=directory),
                  patch.object(ssh_bridge.provision, "safe_file"), patch.object(ssh_bridge.provision, "run") as run):
                args = type("Args", (), dict(config=config, sshd_config="/etc/ssh/sshd_config", ssh_service="ssh",
                                            host_key="/etc/ssh/ssh_host_ed25519_key.pub", sshd_pid_file=None))()
                ssh_bridge.install(args)
            snapshot = json.loads((state / "config.json").read_text())
            self.assertEqual(snapshot["profile"]["ssh"]["port"], 21200)
            self.assertEqual(set(str(path.relative_to(state / "runtime")) for path in (state / "runtime").rglob("*.py")),
                             set(ssh_bridge.RUNTIME_FILES))
            text = writes[Path("/etc/systemd/system") / ssh_bridge.UNIT]
            self.assertIn("Before=docker.service", text)
            self.assertIn("ExecStopPost=", text)
            self.assertNotIn(str(ROOT), text)
            self.assertEqual(run.call_args_list[-1].args[0], ["systemctl", "restart", ssh_bridge.UNIT])

    def test_install_sudo_preserves_the_selected_public_key(self):
        with patch.object(ssh_bridge.os, "geteuid", return_value=1000), patch.object(ssh_bridge.subprocess, "run") as run:
            run.return_value.returncode = 0
            self.assertEqual(ssh_bridge.main(["install", "--config", str(ROOT / "examples/services.token.json"),
                                             "--host-key", "/etc/ssh/custom.pub"]), 0)
        command = run.call_args.args[0]
        self.assertEqual(command[0], "sudo")
        self.assertEqual(command[command.index("--host-key") + 1], "/etc/ssh/custom.pub")


class StaleTokenCleanupTests(unittest.TestCase):
    def test_cleanup_revokes_stale_tokens_and_preserves_another_live_controller(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            metadata = directory / "account.json"
            metadata.touch()
            manager = Mock()
            manager.resolve_token_user.return_value = "svc_tunnel_token1"
            manager.state_path.return_value = metadata
            manager.managed_identity.return_value = ({"auth_mode": "token"}, SimpleNamespace(pw_uid=123456), None)
            snapshot = {"profile": load_profile(ROOT / "examples/services.token.json"),
                        "sshd_config": "/etc/ssh/sshd_config", "ssh_service": "ssh"}
            lock_path = directory / "token.lock"
            def token_lock(path, mode):
                self.assertEqual(path, "/run/lock/sservcli-token-svc_tunnel_token1.lock")
                return lock_path.open(mode)
            with (patch.object(ssh_bridge, "load_snapshot", return_value=snapshot),
                  patch.object(ssh_bridge.provision, "Provisioner", return_value=manager),
                  patch.object(ssh_bridge.provision, "management_lock", side_effect=contextlib.nullcontext),
                  patch.object(ssh_bridge, "open", side_effect=token_lock, create=True)):
                with lock_path.open("a") as live:
                    fcntl.flock(live, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    ssh_bridge.cleanup(directory)
                    manager.managed_identity.assert_not_called()
                    manager.lock_token.assert_not_called()
                ssh_bridge.cleanup(directory)
                manager.lock_token.assert_called_once_with("svc_tunnel_token1", 123456)


if __name__ == "__main__":
    unittest.main()
