"""Token authentication and real Python SSH forwarding, without OS accounts."""
import copy
import json
import os
from pathlib import Path
import socket
import socketserver
import string
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import paramiko

from sservcli.config import ConfigError, load_profile, token_profile, validate_profile, validate_token
from sservcli.token_auth import TOKEN_ALPHABET, generate_token, host_identity, private_directory, read_private, remembered_token, store_token
from sservcli.token_server import TokenAuthority, TokenServer
from sservcli.tunnel import Tunnel

ROOT = Path(__file__).resolve().parents[1]


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_for(predicate, timeout=12):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError("Timed out waiting for token SSH state")


class TokenTests(unittest.TestCase):
    def test_tokens_are_exactly_eight_characters_from_the_case_sensitive_base62_alphabet(self):
        self.assertEqual(len(set(TOKEN_ALPHABET)), 62)
        self.assertEqual(set(TOKEN_ALPHABET), set(string.ascii_letters + string.digits))
        for _ in range(100):
            self.assertRegex(generate_token(), r"\A[A-Za-z0-9]{8}\Z")
        for invalid in ("short", "TooLong123", "1234567!", "가나다라마바사아", "abc_defg", "abcdefgh\n", None):
            with self.subTest(invalid=invalid), self.assertRaises(ConfigError):
                validate_token(invalid)
        with patch("sservcli.token_auth.secrets.choice", side_effect=list("A" * 8 + "b" * 8)):
            self.assertEqual(generate_token("A" * 8), "b" * 8)

    def test_authentication_distinguishes_upper_and_lower_case_and_requires_the_application_user(self):
        authority = TokenAuthority("Ab1Cd2E3")
        self.assertFalse(authority.authenticate("peer", "sservcli", "ab1cd2e3"))
        self.assertFalse(authority.authenticate("peer", "root", "Ab1Cd2E3"))
        self.assertTrue(authority.authenticate("peer", "sservcli", "Ab1Cd2E3"))
        self.assertFalse(authority.authenticate("other", "sservcli", "A" * 100000))

    def test_failed_attempts_are_limited_per_ip_and_globally_and_expire(self):
        now = [0.0]
        authority = TokenAuthority("Ab1Cd2E3", per_ip=2, total=3, window=60, clock=lambda: now[0])
        self.assertFalse(authority.authenticate("one", "sservcli", "bad"))
        self.assertFalse(authority.authenticate("one", "sservcli", "bad"))
        self.assertTrue(authority.blocked("one"))
        self.assertFalse(authority.authenticate("one", "sservcli", "Ab1Cd2E3"))
        self.assertFalse(authority.authenticate("two", "sservcli", "bad"))
        self.assertTrue(authority.blocked("three"))
        self.assertFalse(authority.authenticate("three", "sservcli", "Ab1Cd2E3"))
        now[0] = 61
        self.assertFalse(authority.blocked("one"))
        self.assertTrue(authority.authenticate("one", "sservcli", "Ab1Cd2E3"))

    def test_server_identity_persists_and_private_files_are_protected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "state"
            first, public = host_identity(directory)
            second, again = host_identity(directory)
            self.assertEqual(public, again)
            self.assertEqual(first.asbytes(), second.asbytes())
            self.assertTrue(second.can_sign())
            if os.name != "nt":
                self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
                self.assertEqual((directory / "host_ed25519").stat().st_mode & 0o777, 0o600)

    def test_remembered_tokens_are_separate_from_the_profile_and_can_be_forgotten(self):
        config = load_profile(ROOT / "examples/services.token.json")
        config["ssh"]["host_public_key"] = "ssh-ed25519 fixture-host-identity"
        with tempfile.TemporaryDirectory() as temporary:
            store_token(temporary, config, "Ab1Cd2E3")
            self.assertEqual(remembered_token(temporary, config), "Ab1Cd2E3")
            if os.name == "nt":
                self.assertNotIn("Ab1Cd2E3", (Path(temporary) / "tokens.json").read_text())
            else:
                self.assertEqual((Path(temporary) / "tokens.json").stat().st_mode & 0o777, 0o600)
            other = copy.deepcopy(config)
            other["ssh"]["port"] = 8023
            self.assertIsNone(remembered_token(temporary, other))
            store_token(temporary, config, None)
            self.assertIsNone(remembered_token(temporary, config))
        self.assertNotIn("token", json.dumps(config))

    def test_version_two_has_no_os_user_private_identity_or_token_in_the_json_schema(self):
        legacy = load_profile(ROOT / "examples/services.json")
        config = token_profile(legacy)
        self.assertEqual(config["version"], 2)
        self.assertEqual(config["ssh"]["port"], 8022)
        self.assertNotIn("user", config["ssh"])
        self.assertNotIn("identity_file", config["ssh"])
        self.assertEqual(config["services"], legacy["services"])
        self.assertEqual(legacy["version"], 1)
        self.assertEqual(token_profile(legacy, 8123)["ssh"]["port"], 8123)
        for field in ("token", "identity_file", "user"):
            changed = copy.deepcopy(config)
            changed["ssh"][field] = "Ab1Cd2E3"
            with self.assertRaises(ConfigError):
                validate_profile(changed)


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        value = self.request.recv(65536)
        if value:
            self.request.sendall(self.server.tag + value)


class HalfCloseEcho(socketserver.BaseRequestHandler):
    def handle(self):
        chunks = []
        while chunk := self.request.recv(32768):
            chunks.append(chunk)
        self.request.sendall(self.server.tag + b"".join(chunks))


class TokenSshTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.echoes = []
        for index, handler in enumerate((Echo, Echo, HalfCloseEcho)):
            echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
            echo.daemon_threads = True
            echo.tag = f"service-{index}:".encode()
            threading.Thread(target=echo.serve_forever, daemon=True).start()
            cls.addClassCleanup(echo.server_close)
            cls.addClassCleanup(echo.shutdown)
            cls.echoes.append(echo)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sservcli-token-test-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.config = load_profile(ROOT / "examples/services.token.json")
        self.config["ssh"]["host"] = "127.0.0.1"
        self.config["reconnect"] = {"enabled": True, "max_attempts": 2, "initial_delay_secs": 1, "max_delay_secs": 2}
        for service, echo in zip(self.config["services"], self.echoes):
            service.update(local_port=free_port(), remote_port=echo.server_address[1])
        self.server = TokenServer(self.config, self.directory / "state", listen="127.0.0.1", port=0).start()
        self.addCleanup(self.server.close)
        self.config["ssh"].update(port=self.server.address[1], host_public_key=self.server.public_key)
        self.tunnel = Tunnel()
        self.addCleanup(self.tunnel.disconnect)

    def connect(self, token=None, expected="connected"):
        self.tunnel.connect(self.config, token=token or self.server.token)
        wait_for(lambda: self.tunnel.snapshot()["status"] in ("connected", "failed"))
        state = self.tunnel.snapshot()
        self.assertEqual(state["status"], expected, state["logs"])
        return state

    def roundtrip(self, index=0, value=b"ping"):
        with socket.create_connection(("127.0.0.1", self.config["services"][index]["local_port"]), timeout=3) as client:
            client.sendall(value)
            client.shutdown(socket.SHUT_WR)
            chunks = []
            while chunk := client.recv(65536):
                chunks.append(chunk)
        self.assertEqual(b"".join(chunks), f"service-{index}:".encode() + value)

    def transport(self, *, authenticate=True):
        connection = socket.create_connection(self.server.address[:2], timeout=3)
        transport = paramiko.Transport(connection)
        transport.set_log_channel("sservcli.ssh.test")
        self.addCleanup(transport.close)
        if authenticate:
            transport.connect(hostkey=self.server.host_key, username="sservcli", password=self.server.token)
        else:
            transport.start_client(timeout=3)
        return transport

    def test_all_services_use_one_authenticated_transport_and_cleanup_releases_ports(self):
        self.connect()
        for index in range(3):
            self.roundtrip(index)
        self.assertEqual(self.server.authentications, 1)
        self.tunnel.disconnect()
        for service in self.config["services"]:
            with socket.socket() as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", service["local_port"]))

    def test_large_half_closed_request_is_relayed_without_losing_the_response(self):
        self.connect()
        self.roundtrip(2, os.urandom(256 * 1024))

    def test_wrong_token_is_rejected_without_retrying_or_logging_any_token(self):
        wrong = "AAAAAAAA" if self.server.token != "AAAAAAAA" else "BBBBBBBB"
        state = self.connect(wrong, expected="failed")
        self.assertEqual(self.server.authentications, 0)
        text = "\n".join(state["logs"])
        self.assertIn("Shared token rejected", text)
        self.assertNotIn(wrong, text)
        self.assertNotIn(self.server.token, text)
        self.assertEqual(state["attempt"], 0)

    def test_host_key_is_checked_before_the_token_is_sent(self):
        _, other_public = host_identity(self.directory / "wrong-server")
        self.config["ssh"]["host_public_key"] = other_public
        with patch.object(self.server.authority, "authenticate", wraps=self.server.authority.authenticate) as authenticate:
            state = self.connect(expected="failed")
            authenticate.assert_not_called()
        self.assertIn("host key mismatch", state["message"])

    def test_unpinned_server_is_rejected_before_opening_a_network_connection(self):
        self.config["ssh"].pop("host_public_key")
        with patch("sservcli.token_tunnel.socket.create_connection") as connect:
            with self.assertRaisesRegex(ConfigError, "public host key"):
                self.tunnel.connect(self.config, token=self.server.token)
            connect.assert_not_called()

    def test_fallback_addresses_use_the_same_pinned_key(self):
        self.config["ssh"].update(host="127.0.0.2", fallback_hosts=["127.0.0.1"])
        state = self.connect()
        self.assertEqual(state["active_host"], "127.0.0.1")
        self.assertIn("127.0.0.2", "\n".join(state["logs"]))
        self.roundtrip()
        self.assertEqual(self.server.authentications, 1)

    def test_server_rejects_unlisted_hosts_ports_sessions_remote_forwarding_and_unauthenticated_channels(self):
        transport = self.transport()
        for destination in (("127.0.0.1", 1), ("localhost", self.echoes[0].server_address[1])):
            with self.subTest(destination=destination), self.assertRaises(paramiko.ChannelException):
                transport.open_channel("direct-tcpip", destination, ("127.0.0.1", 12345), timeout=3)
        with self.assertRaises(paramiko.ChannelException):
            transport.open_session(timeout=3)
        with self.assertRaises(paramiko.SSHException):
            transport.request_port_forward("127.0.0.1", 0)
        anonymous = self.transport(authenticate=False)
        with self.assertRaises(paramiko.SSHException):
            anonymous.open_channel("direct-tcpip", ("127.0.0.1", self.echoes[0].server_address[1]), ("127.0.0.1", 12345), timeout=3)

    def test_dropped_transport_reconnects_all_services(self):
        self.connect()
        with self.server.lock:
            active = list(self.server.transports)
        for transport in active:
            transport.close()
        wait_for(lambda: self.server.authentications >= 2 and self.tunnel.snapshot()["status"] == "connected")
        self.roundtrip()

    def test_disconnect_interrupts_an_unresponsive_ssh_handshake(self):
        accepted, release = threading.Event(), threading.Event()
        class Stall(socketserver.BaseRequestHandler):
            def handle(self):
                accepted.set()
                release.wait(5)
        stalled = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Stall)
        stalled.daemon_threads = True
        threading.Thread(target=stalled.serve_forever, daemon=True).start()
        try:
            self.config["ssh"]["port"] = stalled.server_address[1]
            self.tunnel.connect(self.config, token=self.server.token)
            self.assertTrue(accepted.wait(2))
            wait_for(lambda: self.tunnel._cancel is not None, timeout=2)
            started = time.monotonic()
            self.tunnel.disconnect()
            self.assertLess(time.monotonic() - started, 3)
            self.assertEqual(self.tunnel.snapshot()["status"], "disconnected")
        finally:
            release.set()
            stalled.shutdown()
            stalled.server_close()

    def test_restart_rotates_the_token_preserves_host_identity_and_rejects_the_previous_token(self):
        old_token, old_public = self.server.token, self.server.public_key
        port = self.server.address[1]
        self.server.close()
        self.server = TokenServer(self.config, self.directory / "state", listen="127.0.0.1", port=port).start()
        self.addCleanup(self.server.close)
        self.assertNotEqual(self.server.token, old_token)
        self.assertEqual(self.server.public_key, old_public)
        self.assertEqual(read_private(self.directory / "state/access.token").strip(), self.server.token)
        self.connect(old_token, expected="failed")
        self.tunnel.disconnect()
        self.connect()
        self.roundtrip()

    def test_a_second_server_cannot_rotate_the_running_servers_token(self):
        old = read_private(self.directory / "state/access.token")
        second = TokenServer(self.config, self.directory / "state", listen="127.0.0.1", port=0)
        self.addCleanup(second.close)
        with self.assertRaisesRegex(ConfigError, "already in use"):
            second.start()
        self.assertEqual(read_private(self.directory / "state/access.token"), old)

    def test_redirected_server_output_does_not_contain_the_startup_token(self):
        config = copy.deepcopy(self.config)
        config["ssh"]["port"] = free_port()
        path = self.directory / "cli-profile.json"
        path.write_text(json.dumps(config))
        state_dir = self.directory / "cli-state"
        log_path = self.directory / "server.log"
        with log_path.open("w") as log:
            process = subprocess.Popen([sys.executable, "-m", "sservcli", "serve", "--config", str(path), "--state-dir", str(state_dir), "--listen", "127.0.0.1"], stdout=log, stderr=log)
            try:
                wait_for(lambda: (state_dir / "access.token").exists())
                token = read_private(state_dir / "access.token").strip()
                self.assertRegex(token, r"\A[A-Za-z0-9]{8}\Z")
                wait_for(lambda: "Token file:" in log_path.read_text())
                self.assertNotIn(token, log_path.read_text())
            finally:
                process.terminate()
                process.wait(timeout=10)
        if os.name != "nt":
            self.assertEqual(process.returncode, 0)


if __name__ == "__main__":
    unittest.main()
