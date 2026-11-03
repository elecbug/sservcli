"""Cross-platform client behavior, configuration, and process boundaries."""
import copy
import json
import os
from pathlib import Path
import queue
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from sservcli.config import ConfigError, launch_arguments, load_profile, resolved_profile, save_profile, validate_profile
from sservcli.instance import Instance
from sservcli.tunnel import Tunnel, check_ports, launch_service, prepare_host_key, ssh_arguments

ROOT = Path(__file__).resolve().parents[1]


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((ROOT / "examples/services.json").read_text())
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def test_examples_validate_and_cli_lists_enabled_and_disabled_services(self):
        self.config["services"][1]["enabled"] = False
        path = self.directory / "services.json"
        save_profile(path, self.config)
        output = subprocess.run([sys.executable, "-m", "sservcli", "list", "--config", str(path)], capture_output=True, text=True, check=True).stdout
        self.assertIn("http://127.0.0.1:18080/", output)
        self.assertIn("disabled", output)
        self.assertIn("127.0.0.1:15432", output)
        validate_profile(load_profile(ROOT / "examples/services.windows.json"))

    def test_strict_validation_rejects_unknown_fields_and_unsafe_values(self):
        changes = [lambda c: c["ssh"].update(port=True), lambda c: c.update(version=True),
                   lambda c: c["ssh"].update(host="-oProxyCommand=anything"),
                   lambda c: c["ssh"].update(fallback_hosts=[c["ssh"]["host"]]),
                   lambda c: c["ssh"].update(fallback_hosts="192.0.2.1"),
                   lambda c: c["ssh"].update(identity_file="/tmp/%d/key"),
                   lambda c: c["services"][0].update(remote_host="0.0.0.0"),
                   lambda c: c["services"][0].update(local_port=22),
                   lambda c: c["services"][0].update(path="//example.com"),
                   lambda c: c["services"][0].update(path="/\\example.com"),
                   lambda c: c["services"][0].update(launch=["tool", "{unknown}"]),
                   lambda c: c["services"][0].update(launch="tool"),
                   lambda c: c["ssh"].update(typo="value"),
                   lambda c: c["ssh"].update(host_public_key="ssh-ed25519 " + "A" * 32)]
        for change in changes:
            config = copy.deepcopy(self.config)
            change(config)
            with self.subTest(change=change), self.assertRaises(ConfigError):
                validate_profile(config)

    def test_relative_and_home_paths_resolve_without_mutating_profile(self):
        self.config["ssh"]["identity_file"] = "keys/identity"
        self.config["ssh"]["known_hosts_file"] = "~/.ssh/known_hosts"
        resolved = resolved_profile(self.config, self.directory / "services.json")
        self.assertEqual(resolved["ssh"]["identity_file"], str(self.directory / "keys/identity"))
        self.assertEqual(resolved["ssh"]["known_hosts_file"], str(Path.home() / ".ssh/known_hosts"))
        self.assertEqual(self.config["ssh"]["identity_file"], "keys/identity")

    def test_profile_save_is_exclusive_and_handles_unicode_and_bom(self):
        self.config["name"] = "테스트 서버"
        path = self.directory / "profile.json"
        save_profile(path, self.config, exclusive=True)
        previous = path.read_bytes()
        with self.assertRaises(FileExistsError):
            save_profile(path, self.config, exclusive=True)
        self.assertEqual(path.read_bytes(), previous)
        path.write_bytes(b"\xef\xbb\xbf" + previous)
        self.assertEqual(load_profile(path), self.config)

    def test_one_ssh_command_uses_all_enabled_forwards_and_enforces_public_key_auth(self):
        self.config["services"][2]["enabled"] = False
        args = ssh_arguments(self.config, "C:/Users/Some User/known_hosts")
        self.assertEqual(args.count("-L"), 2)
        self.assertIn("127.0.0.1:18080:127.0.0.1:8080", args)
        for option in ("BatchMode=yes", "StrictHostKeyChecking=yes", "ExitOnForwardFailure=yes", "PasswordAuthentication=no", "ForwardAgent=no", "IdentitiesOnly=yes"):
            self.assertIn(option, args)
        self.assertIn('UserKnownHostsFile="C:/Users/Some User/known_hosts"', args)
        self.assertEqual(args[:2], ["-F", "none"])
        self.assertEqual(args[-1], self.config["ssh"]["host"])
        self.config["ssh"]["identity_file"] = None
        self.assertNotIn("IdentitiesOnly=yes", ssh_arguments(self.config, "known_hosts"))

    def test_launch_preserves_arguments_without_using_a_shell(self):
        service = self.config["services"][0]
        service["launch"] = ["browser", "{url}", "literal; value with spaces"]
        self.assertEqual(launch_arguments(service), ["browser", "http://127.0.0.1:18080/", "literal; value with spaces"])
        with patch("sservcli.tunnel.subprocess.Popen") as popen:
            launch_service(service)
            self.assertEqual(popen.call_args.args[0], launch_arguments(service))
            self.assertIs(popen.call_args.kwargs["shell"], False)
        service["enabled"] = False
        with self.assertRaises(ConfigError):
            launch_service(service)

    def test_occupied_port_fails_before_any_ssh_process_is_created(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            self.config["services"][0]["local_port"] = listener.getsockname()[1]
            self.config["ssh"]["identity_file"] = None
            self.config["ssh"]["known_hosts_file"] = str(self.directory / "known_hosts")
            (self.directory / "known_hosts").touch()
            with patch("sservcli.tunnel.subprocess.Popen") as popen:
                with self.assertRaisesRegex(ConfigError, "unavailable"):
                    Tunnel().connect(self.config)
                popen.assert_not_called()

    def test_no_enabled_services_is_an_error(self):
        for service in self.config["services"]:
            service["enabled"] = False
        with self.assertRaisesRegex(ConfigError, "at least one"):
            check_ports(self.config)

    def test_pinned_key_is_validated_and_applies_to_every_address(self):
        key = self.directory / "host"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
        self.config["ssh"].update(host="192.0.2.1", fallback_hosts=["192.0.2.2", "2001:db8::1"],
                                  port=2222, host_public_key=key.with_suffix(".pub").read_text())
        with tempfile.TemporaryDirectory() as temporary:
            path, fingerprint = prepare_host_key(self.config["ssh"], temporary)
            lines = Path(path).read_text().splitlines()
            self.assertEqual(len(lines), 3)
            self.assertTrue(lines[0].startswith("[192.0.2.1]:2222 ssh-ed25519 "))
            self.assertTrue(lines[2].startswith("[2001:db8::1]:2222 ssh-ed25519 "))
            actual = subprocess.run(["ssh-keygen", "-lf", str(key.with_suffix(".pub"))], capture_output=True, text=True, check=True).stdout
            self.assertIn(fingerprint, actual)

    def test_second_desktop_instance_shows_existing_window_without_starting_tunnels(self):
        actions = queue.Queue()
        owner = Instance(self.directory, actions)
        self.addCleanup(owner.close)
        self.assertTrue(owner.acquire())
        second = Instance(self.directory, queue.Queue())
        self.addCleanup(second.close)
        self.assertFalse(second.acquire())
        self.assertEqual(actions.get(timeout=2), "show")
        with socket.create_connection(owner.server.getsockname(), timeout=2) as connection:
            connection.sendall(b"wrong token\n")
        with self.assertRaises(queue.Empty):
            actions.get(timeout=0.3)


if __name__ == "__main__":
    unittest.main()
