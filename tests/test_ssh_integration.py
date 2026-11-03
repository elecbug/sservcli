"""Opt-in, unprivileged local OpenSSH tests. No existing SSH config is changed."""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("server", ROOT / "server/sservcli_server.py")
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for(predicate, timeout=12):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError("Timed out waiting for the expected SSH state")


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        value = self.request.recv(1024)
        if value:
            self.request.sendall(self.server.tag + value)


@unittest.skipUnless(os.environ.get("SSERVCLI_SSH_TESTS") == "1", "Run make integration to enable local sshd tests")
class SshIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sservcli-test-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.sshd = shutil.which("sshd") or "/usr/sbin/sshd"
        if not Path(self.sshd).is_file():
            self.skipTest("OpenSSH server is required (install openssh-server)")
        self.binary = Path(os.environ.get("SSERVCLI_BIN", ROOT / "target/debug/sservcli"))
        self.assertTrue(self.binary.is_file(), "Run cargo build first")
        self.user = pwd.getpwuid(os.getuid()).pw_name
        for name in ("host", "identity", "wrong_host"):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.directory / name)], check=True)
        self.port = free_port()
        self.echoes = []
        services = []
        for index in range(3):
            echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
            echo.daemon_threads = True
            echo.tag = f"service-{index}:".encode()
            threading.Thread(target=echo.serve_forever, daemon=True).start()
            self.addCleanup(echo.server_close)
            self.addCleanup(echo.shutdown)
            self.echoes.append(echo)
            services.append({"id": f"svc{index}", "name": f"Service {index}", "kind": "tcp",
                             "remote_host": "127.0.0.1", "remote_port": echo.server_address[1],
                             "local_port": free_port(), "enabled": True})
        permitted = [f"127.0.0.1:{s['remote_port']}" for s in services]
        auth = self.directory / "authorized_keys"
        auth.write_text(server.restricted_key((self.directory / "identity.pub").read_text(), permitted))
        known = self.directory / "known_hosts"
        known.write_text(f"[127.0.0.1]:{self.port} " + (self.directory / "host.pub").read_text())
        self.profile = {"version": 1, "name": "Integration test", "ssh": {
            "host": "127.0.0.1", "port": self.port, "user": self.user,
            "identity_file": str(self.directory / "identity"), "known_hosts_file": str(known)},
            "reconnect": {"enabled": True, "max_attempts": 2, "initial_delay_secs": 1, "max_delay_secs": 2},
            "services": services}
        # Match policy comes from the actual server renderer. Override only the
        # fixture key path; the logged-in user's real authorized_keys is never read.
        block = server.policy(self.user, permitted).replace(f"/home/{self.user}/.ssh/authorized_keys", str(auth))
        config = self.directory / "sshd_config"
        config.write_text(f"Port {self.port}\nListenAddress 127.0.0.1\nHostKey {self.directory / 'host'}\n"
                          f"PidFile {self.directory / 'sshd.pid'}\nStrictModes no\nUsePAM no\nLogLevel VERBOSE\n" + block)
        validated = subprocess.run([self.sshd, "-t", "-f", str(config)], capture_output=True, text=True)
        self.assertEqual(validated.returncode, 0, validated.stderr)
        self.daemon_log_path = self.directory / "sshd.log"
        daemon_log = self.daemon_log_path.open("w")
        self.addCleanup(daemon_log.close)
        self.daemon = subprocess.Popen([self.sshd, "-D", "-e", "-f", str(config)], stdout=subprocess.DEVNULL, stderr=daemon_log, start_new_session=True)
        self.addCleanup(self.stop_daemon)
        wait_for(lambda: "Server listening" in self.daemon_log_path.read_text())
        self.cli = None

    def stop_daemon(self):
        if self.daemon.poll() is None:
            os.killpg(self.daemon.pid, signal.SIGTERM)
            self.daemon.wait(timeout=5)

    def start_client(self):
        path = self.directory / "services.json"
        path.write_text(json.dumps(self.profile))
        self.cli_log_path = self.directory / "client.log"
        log = self.cli_log_path.open("w")
        self.addCleanup(log.close)
        self.cli = subprocess.Popen([str(self.binary), "connect", "--config", str(path)], stderr=log, stdout=subprocess.DEVNULL)
        self.addCleanup(self.stop_client)

    def stop_client(self):
        if self.cli and self.cli.poll() is None:
            self.cli.terminate()
            try:
                self.cli.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.cli.kill()
                self.cli.wait(timeout=5)

    def connected(self, count=1):
        def ready():
            if self.cli.poll() is not None:
                self.fail(self.cli_log_path.read_text() + "\n" + self.daemon_log_path.read_text())
            return self.cli_log_path.read_text().count("[connected]") >= count
        wait_for(ready)

    def test_multiple_services_one_connection_and_clean_disconnect(self):
        self.start_client()
        self.connected()
        for index, service in enumerate(self.profile["services"]):
            with socket.create_connection(("127.0.0.1", service["local_port"]), timeout=3) as sock:
                sock.sendall(b"ping")
                self.assertEqual(sock.recv(1024), f"service-{index}:ping".encode())
        self.assertEqual(self.daemon_log_path.read_text().count("Accepted publickey"), 1)
        self.stop_client()
        self.assertEqual(self.cli.returncode, 0)
        for service in self.profile["services"]:
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", service["local_port"]))
        self.assertEqual(list(Path("/tmp").glob(f"sservcli-{self.cli.pid}-*")), [])

    def test_changed_host_key_fails_without_retries(self):
        (self.directory / "known_hosts").write_text(f"[127.0.0.1]:{self.port} " + (self.directory / "wrong_host.pub").read_text())
        self.start_client()
        self.cli.wait(timeout=10)
        self.assertNotEqual(self.cli.returncode, 0)
        self.assertIn("HOST IDENTIFICATION HAS CHANGED", self.cli_log_path.read_text())
        self.assertNotIn("[reconnecting]", self.cli_log_path.read_text())

    def test_unknown_host_key_is_not_accepted(self):
        (self.directory / "known_hosts").write_text("")
        self.start_client()
        self.cli.wait(timeout=10)
        self.assertNotEqual(self.cli.returncode, 0)
        self.assertIn("Host key verification failed", self.cli_log_path.read_text())
        self.assertEqual((self.directory / "known_hosts").read_text(), "")

    def test_dropped_transport_reconnects(self):
        if not Path("/proc/self").exists():
            self.skipTest("Child-process inspection for this test requires Linux /proc")
        self.start_client()
        self.connected()
        # Linux attributes forked children to the thread that spawned them.
        children = [pid for path in Path(f"/proc/{self.cli.pid}/task").glob("*/children") for pid in path.read_text().split()]
        self.assertEqual(len(children), 1, children)
        os.kill(int(children[0]), signal.SIGTERM)
        self.connected(count=2)
        self.assertEqual(self.daemon_log_path.read_text().count("Accepted publickey"), 2)
        service = self.profile["services"][0]
        with socket.create_connection(("127.0.0.1", service["local_port"]), timeout=3) as sock:
            sock.sendall(b"again")
            self.assertEqual(sock.recv(1024), b"service-0:again")

    def test_server_rejects_unlisted_destination(self):
        forbidden = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
        forbidden.daemon_threads = True
        forbidden.tag = b"forbidden:"
        threading.Thread(target=forbidden.serve_forever, daemon=True).start()
        self.addCleanup(forbidden.server_close)
        self.addCleanup(forbidden.shutdown)
        with socket.create_connection(forbidden.server_address, timeout=3) as sock:
            sock.sendall(b"direct")
            self.assertEqual(sock.recv(1024), b"forbidden:direct")
        self.profile["services"][0]["remote_port"] = forbidden.server_address[1]
        self.start_client()
        self.connected()
        with socket.create_connection(("127.0.0.1", self.profile["services"][0]["local_port"]), timeout=3) as sock:
            sock.sendall(b"forbidden")
            with contextlib.suppress(ConnectionResetError):
                self.assertEqual(sock.recv(1024), b"")
        self.assertIsNone(self.cli.poll())  # Listener readiness does not imply service health.

    def test_recovery_stops_after_retry_budget(self):
        if not Path("/proc/self").exists():
            self.skipTest("Child-process inspection for this test requires Linux /proc")
        self.start_client()
        self.connected()
        self.stop_daemon()
        # Stop the managed client transport explicitly as sshd may have forked
        # authenticated descendants into a separate process group.
        for path in Path(f"/proc/{self.cli.pid}/task").glob("*/children"):
            for child in path.read_text().split():
                with contextlib.suppress(ProcessLookupError):
                    os.kill(int(child), signal.SIGTERM)
        self.cli.wait(timeout=15)
        self.assertNotEqual(self.cli.returncode, 0)
        self.assertEqual(self.cli_log_path.read_text().count("[reconnecting]"), 2)
        self.assertIn("[failed]", self.cli_log_path.read_text())

    def test_shell_and_remote_forwarding_are_denied(self):
        base = ["ssh", "-F", "none", "-i", str(self.directory / "identity"), "-p", str(self.port), "-l", self.user,
                "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", f"UserKnownHostsFile={self.directory / 'known_hosts'}", "-o", "ExitOnForwardFailure=yes"]
        shell = subprocess.run([*base, "127.0.0.1", "true"], text=True, capture_output=True, timeout=5)
        self.assertNotEqual(shell.returncode, 0)
        remote = subprocess.run([*base, "-N", "-R", f"127.0.0.1:{free_port()}:127.0.0.1:80", "127.0.0.1"], text=True, capture_output=True, timeout=5)
        self.assertNotEqual(remote.returncode, 0)
        self.assertIn("remote port forwarding failed", remote.stderr)


if __name__ == "__main__":
    unittest.main()
