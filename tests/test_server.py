import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("server", ROOT / "server/sservcli_server.py")
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)


class PolicyTests(unittest.TestCase):
    def test_profile_and_restrictions(self):
        args = argparse.Namespace(config=ROOT / "client/examples/services.json", user=None, permit_open=None)
        user, permitted = server.policy_input(args)
        text = server.policy(user, permitted)
        self.assertEqual(user, "svc_tunnel")
        self.assertIn("    MaxSessions 0\n", text)
        self.assertIn("    AllowTcpForwarding local\n", text)
        self.assertIn("    PermitOpen 127.0.0.1:8080 127.0.0.1:5432 127.0.0.1:9000\n", text)
        self.assertEqual(server.managed_block(text, user)[0], text)

    def test_rejects_unsafe_accounts_and_destinations(self):
        for user in ("root", "x\nMatch all", "-n", "user,name", "a" * 33):
            with self.subTest(user=user), self.assertRaises(server.SetupError):
                server.username(user)
        for permitted in ([], ["*:*"], ["127.0.0.1:0"], ["127.0.0.1:65536"], ["127.0.0.1:99999"], ["localhost:8080"], ["127.0.0.1:80\nPermitOpen any"]):
            with self.subTest(permitted=permitted), self.assertRaises(server.SetupError):
                server.destinations(permitted)

    def test_key_restrictions_and_key_format(self):
        # The wire key is checked by ssh-keygen separately in the SSH integration test.
        with patch.object(server, "run") as run:
            text = server.restricted_key("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test\n", ["127.0.0.1:8080"])
            self.assertTrue(text.startswith('restrict,port-forwarding,permitopen="127.0.0.1:8080" '))
            self.assertEqual(run.call_args.args[0][:2], ["ssh-keygen", "-lf"])
        for text in ("ssh-ed25519 a\nssh-ed25519 b\n", 'command="id" ssh-ed25519 AAAA', "ssh-rsa AAAA", "ssh-ed25519 AAAA\n\n"):
            with self.subTest(text=text), self.assertRaises(server.SetupError):
                server.restricted_key(text, ["127.0.0.1:80"])

    def test_modified_or_duplicate_blocks_are_not_removed(self):
        text = server.policy("svc_tunnel", ["127.0.0.1:80"])
        for invalid in (text + text, text.replace("Match all\n", ""), text.replace("# END", "# EDITED")):
            with self.assertRaises(server.SetupError):
                server.managed_block(invalid, "svc_tunnel")


class TransactionTests(unittest.TestCase):
    """Real temporary files; only account/systemd/ownership operations are mocked."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        args = argparse.Namespace(sshd_config=str(root / "sshd_config"), ssh_service="ssh", client_address="127.0.0.1")
        self.p = server.Provisioner(args)
        self.p.state_dir = root / "state"
        self.p.home_base = root / "homes"
        self.p.home_base.mkdir()
        self.p.config.write_text("Port 22\n# administrator settings\n")
        self.original = self.p.config.read_text()
        self.key = root / "public.pub"
        self.key.write_text("ssh-ed25519 AAAA fixture\n")
        self.accounts = {}
        for target, replacement in (
            ("safe_file", lambda path: path.stat()),
            ("ensure_state_dir", lambda path: path.mkdir(mode=0o700, exist_ok=True)),
            ("account", lambda user: self.accounts.get(user)),
            ("restricted_key", lambda text, permitted: text),
            ("run", self.run_command),
        ):
            mock = patch.object(server, target, replacement)
            mock.start()
            self.addCleanup(mock.stop)
        for target in ("chown", "fchown"):
            mock = patch.object(server.os, target)
            mock.start()
            self.addCleanup(mock.stop)
        self.syntax = patch.object(self.p, "syntax").start()
        self.audit = patch.object(self.p, "audit").start()
        self.reload = patch.object(self.p, "reload").start()
        self.addCleanup(patch.stopall)
        self.fail_delete = False
        self.denied_at_delete = False

    def run_command(self, argv, **kwargs):
        if argv[0] == "useradd":
            user = argv[-1]
            home = self.p.home_base / user
            self.accounts[user] = SimpleNamespace(pw_uid=12345, pw_dir=str(home), pw_shell="/usr/sbin/nologin")
        if argv[0] == "userdel":
            user = argv[-1]
            self.denied_at_delete = f"DenyUsers {user}" in self.p.config.read_text()
            if self.fail_delete:
                return SimpleNamespace(returncode=1, stderr="fixture deletion failure")
            self.accounts.pop(user, None)
            shutil.rmtree(self.p.home_base / user)
        return SimpleNamespace(returncode=0, stderr="", stdout="")

    def install(self):
        self.p.install("svc_tunnel", ["127.0.0.1:8080"], self.key)

    def test_install_and_remove(self):
        def before_reload():
            self.assertFalse((self.p.home_base / "svc_tunnel/.ssh/authorized_keys").exists())
        self.reload.side_effect = before_reload
        self.install()
        self.reload.side_effect = None
        self.assertIn("svc_tunnel", self.accounts)
        key = self.p.home_base / "svc_tunnel/.ssh/authorized_keys"
        self.assertEqual(key.stat().st_mode & 0o777, 0o644)
        self.assertEqual(key.parent.stat().st_mode & 0o777, 0o755)
        self.assertIn("MaxSessions 0", self.p.config.read_text())
        self.assertTrue(self.p.state_path("svc_tunnel").is_file())
        self.p.remove("svc_tunnel")
        self.assertTrue(self.denied_at_delete)
        self.assertNotIn("svc_tunnel", self.accounts)
        self.assertFalse(self.p.state_path("svc_tunnel").exists())
        self.assertEqual(self.p.config.read_text().strip(), self.original.strip())

    def test_audit_failure_rolls_back_file_and_account(self):
        self.audit.side_effect = server.SetupError("fixture earlier Match policy")
        with self.assertRaisesRegex(server.SetupError, "earlier Match"):
            self.install()
        self.assertEqual(self.p.config.read_text(), self.original)
        self.assertEqual(self.accounts, {})
        self.assertFalse(self.p.state_path("svc_tunnel").exists())

    def test_reload_failure_rolls_back_and_reloads_original(self):
        self.reload.side_effect = [server.SetupError("fixture reload failure"), None]
        with self.assertRaisesRegex(server.SetupError, "reload failure"):
            self.install()
        self.assertEqual(self.reload.call_count, 2)
        self.assertEqual(self.p.config.read_text(), self.original)
        self.assertEqual(self.accounts, {})

    def test_account_deletion_failure_restores_restrictions(self):
        self.install()
        before = self.p.config.read_text()
        self.fail_delete = True
        with self.assertRaisesRegex(server.SetupError, "Could not remove"):
            self.p.remove("svc_tunnel")
        self.assertEqual(self.p.config.read_text(), before)
        self.assertIn("svc_tunnel", self.accounts)

    def test_cleanup_reload_failure_retains_denial_and_metadata(self):
        self.install()
        self.reload.side_effect = [None, server.SetupError("fixture cleanup reload"), None]
        with self.assertRaisesRegex(server.SetupError, "denying block"):
            self.p.remove("svc_tunnel")
        self.assertNotIn("svc_tunnel", self.accounts)
        self.assertIn("DenyUsers svc_tunnel", self.p.config.read_text())
        self.assertTrue(self.p.state_path("svc_tunnel").exists())
        self.reload.side_effect = None
        self.p.remove("svc_tunnel")
        self.assertFalse(self.p.state_path("svc_tunnel").exists())
        self.assertNotIn("DenyUsers", self.p.config.read_text())

    def test_existing_or_modified_accounts_are_protected(self):
        self.install()
        with self.assertRaisesRegex(server.SetupError, "already exists"):
            self.install()
        self.accounts["svc_tunnel"].pw_uid = 99999
        with self.assertRaisesRegex(server.SetupError, "properties changed"):
            self.p.remove("svc_tunnel")
        self.assertIn("svc_tunnel", self.accounts)

    def test_edited_policy_cannot_be_deleted(self):
        self.install()
        self.p.config.write_text(self.p.config.read_text().replace("MaxSessions 0", "MaxSessions 1"))
        with self.assertRaisesRegex(server.SetupError, "metadata differs"):
            self.p.remove("svc_tunnel")


if __name__ == "__main__":
    unittest.main()
