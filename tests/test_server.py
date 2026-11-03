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

    def test_key_merge_matches_identity_without_comment_and_preserves_other_entries(self):
        with patch.object(server, "run"):
            old = server.restricted_key("ssh-ed25519 AAAA old comment\n", ["127.0.0.1:8080"])
            other = server.restricted_key("ssh-ed25519 BBBB other device\n", ["127.0.0.1:5432"])
            original = "# administrator comment\n" + old + other
            merged, status = server.merge_key(original, "ssh-ed25519 AAAA new comment\n", ["127.0.0.1:8080"])
            self.assertEqual((merged, status), (original, "unchanged"))
            merged, status = server.merge_key(original, "ssh-ed25519 AAAA\n", ["127.0.0.1:9000"])
            self.assertEqual(status, "updated")
            self.assertEqual(merged.count("ssh-ed25519 AAAA"), 1)
            self.assertIn('permitopen="127.0.0.1:8080",permitopen="127.0.0.1:9000" ssh-ed25519 AAAA old comment', merged)
            self.assertTrue(merged.endswith(other))
            again, status = server.merge_key(merged, "ssh-ed25519 AAAA\n", ["127.0.0.1:9000"])
            self.assertEqual((again, status), (merged, "unchanged"))

    def test_key_merge_ignores_comments_and_leaves_administrator_key_options_intact(self):
        with patch.object(server, "run"):
            original = '# ssh-ed25519 AAAA inactive\nssh-ed25519 BBBB comment with unmatched "quote'
            merged, status = server.merge_key(original, "ssh-ed25519 AAAA\n", ["127.0.0.1:8080"])
            self.assertEqual(status, "added")
            self.assertTrue(merged.startswith(original + "\n"))
            self.assertIn('permitopen="127.0.0.1:8080" ssh-ed25519 AAAA\n', merged)
            original = 'from="192.0.2.1",command="echo ssh-ed25519 AAAA" ssh-ed25519 BBBB comment\n'
            self.assertEqual(server.merge_key(original, "ssh-ed25519 BBBB\n", ["127.0.0.1:8080"]), (original, "unchanged"))
            # All 64 destinations may be repeated without tripping the unique limit.
            allowed = [f"127.0.0.1:{port}" for port in range(1000, 1064)]
            original = server.restricted_key("ssh-ed25519 AAAA\n", allowed)
            self.assertEqual(server.merge_key(original, "ssh-ed25519 AAAA\n", allowed), (original, "unchanged"))


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
        self.commands = []
        for target, replacement in (
            ("safe_file", lambda path: path.stat()),
            ("safe_directory", lambda path: path.stat()),
            ("ensure_state_dir", lambda path: path.mkdir(mode=0o700, exist_ok=True)),
            ("account", lambda user: self.accounts.get(user)),
            ("restricted_key", lambda text, permitted: server.key_options(permitted) + " " + text.rstrip() + "\n"),
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
        self.commands.append(argv)
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

    def test_ensure_is_idempotent_for_a_managed_account_and_deduplicates_the_key(self):
        first = self.p.ensure("svc_tunnel", ["127.0.0.1:8080"], self.key)
        home = self.p.home_base / "svc_tunnel"
        key_file = home / ".ssh/authorized_keys"
        previous = (self.p.config.read_bytes(), self.p.state_path("svc_tunnel").read_bytes(), key_file.read_bytes())
        inode = key_file.stat().st_ino
        self.key.write_text("ssh-ed25519 AAAA different comment\n")
        second = self.p.ensure("svc_tunnel", ["127.0.0.1:8080"], self.key)
        self.assertTrue(first["created"])
        self.assertEqual(second, {"user": "svc_tunnel", "created": False, "account": "reused", "key": "unchanged"})
        self.assertEqual(previous, (self.p.config.read_bytes(), self.p.state_path("svc_tunnel").read_bytes(), key_file.read_bytes()))
        self.assertEqual(key_file.stat().st_ino, inode)
        self.assertEqual(sum(command[0] == "useradd" for command in self.commands), 1)
        self.assertEqual(self.reload.call_count, 1)

    def test_ensure_adds_a_key_and_extends_policy_without_removing_previous_destinations(self):
        self.install()
        key_file = self.p.home_base / "svc_tunnel/.ssh/authorized_keys"
        original = key_file.read_text()
        self.key.write_text("ssh-ed25519 BBBB second device\n")
        result = self.p.ensure("svc_tunnel", ["127.0.0.1:9000"], self.key)
        self.assertFalse(result["created"])
        self.assertEqual(result["key"], "added")
        self.assertTrue(key_file.read_text().startswith(original))
        self.assertIn('permitopen="127.0.0.1:9000" ssh-ed25519 BBBB', key_file.read_text())
        self.assertIn("PermitOpen 127.0.0.1:8080 127.0.0.1:9000\n", self.p.config.read_text())
        record = json.loads(self.p.state_path("svc_tunnel").read_text())
        import hashlib
        self.assertEqual(record["block_sha256"], hashlib.sha256(server.managed_block(self.p.config.read_text(), "svc_tunnel")[0].encode()).hexdigest())
        self.assertEqual(self.p.ensure("svc_tunnel", ["127.0.0.1:9000"], self.key)["key"], "unchanged")
        self.assertEqual(self.p.audit_destinations("svc_tunnel", ["127.0.0.1:9000"]), ["127.0.0.1:8080", "127.0.0.1:9000"])
        with self.assertRaisesRegex(server.SetupError, "does not permit"):
            self.p.audit_destinations("svc_tunnel", ["127.0.0.1:9999"])
        self.p.remove("svc_tunnel")  # The refreshed metadata still supports explicit removal.

    def test_ensure_extends_the_existing_key_without_duplicates(self):
        self.install()
        result = self.p.ensure("svc_tunnel", ["127.0.0.1:9000"], self.key)
        key = (self.p.home_base / "svc_tunnel/.ssh/authorized_keys").read_text()
        self.assertEqual(result["key"], "updated")
        self.assertEqual(key.count("ssh-ed25519 AAAA"), 1)
        self.assertIn('permitopen="127.0.0.1:8080",permitopen="127.0.0.1:9000"', key)

    def test_ensure_leaves_an_external_account_untouched(self):
        self.accounts["existing"] = SimpleNamespace(pw_uid=12345, pw_dir="/home/existing", pw_shell="/bin/bash")
        result = self.p.ensure("existing", ["127.0.0.1:8080"], self.key)
        self.assertEqual((result["created"], result["account"], result["key"]), (False, "external", "unchanged"))
        self.assertEqual(self.commands, [])
        self.assertEqual(self.p.config.read_text(), self.original)
        self.assertFalse(self.p.state_path("existing").exists())
        self.assertEqual(self.accounts["existing"].pw_shell, "/bin/bash")

    def test_failed_key_update_restores_policy_metadata_and_keys_without_deleting_account(self):
        self.install()
        state_path = self.p.state_path("svc_tunnel")
        key_file = self.p.home_base / "svc_tunnel/.ssh/authorized_keys"
        before = (self.p.config.read_bytes(), state_path.read_bytes(), key_file.read_bytes())
        self.reload.side_effect = [server.SetupError("fixture update reload"), None]
        with self.assertRaisesRegex(server.SetupError, "update reload"):
            self.p.ensure("svc_tunnel", ["127.0.0.1:9000"], self.key)
        self.assertEqual(before, (self.p.config.read_bytes(), state_path.read_bytes(), key_file.read_bytes()))
        self.assertIn("svc_tunnel", self.accounts)
        self.assertFalse(any(command[0] == "userdel" for command in self.commands))

    def test_failed_key_write_restores_all_files_and_keeps_the_existing_account(self):
        self.install()
        state_path = self.p.state_path("svc_tunnel")
        key_file = self.p.home_base / "svc_tunnel/.ssh/authorized_keys"
        before = (self.p.config.read_bytes(), state_path.read_bytes(), key_file.read_bytes())
        atomic = server.atomic_write
        failed = False
        def fail_key_once(path, text, **kwargs):
            nonlocal failed
            if path == key_file and not failed:
                failed = True
                raise OSError("fixture key write failure")
            return atomic(path, text, **kwargs)
        with patch.object(server, "atomic_write", side_effect=fail_key_once), self.assertRaisesRegex(OSError, "key write failure"):
            self.p.ensure("svc_tunnel", ["127.0.0.1:9000"], self.key)
        self.assertEqual(before, (self.p.config.read_bytes(), state_path.read_bytes(), key_file.read_bytes()))
        self.assertIn("svc_tunnel", self.accounts)
        self.assertFalse(any(command[0] == "userdel" for command in self.commands))

    def test_ensure_refuses_altered_metadata_or_user_properties_without_changes(self):
        self.install()
        before = self.p.config.read_bytes()
        self.accounts["svc_tunnel"].pw_uid = 99999
        with self.assertRaisesRegex(server.SetupError, "properties changed"):
            self.p.ensure("svc_tunnel", ["127.0.0.1:9000"], self.key)
        self.assertEqual(self.p.config.read_bytes(), before)
        self.assertIn("svc_tunnel", self.accounts)

    def test_useradd_collision_never_deletes_the_other_created_account(self):
        original_run = self.run_command
        def collide(argv, **kwargs):
            result = original_run(argv, **kwargs)
            if argv[0] == "useradd":
                raise server.SetupError("account already exists from concurrent administrator")
            return result
        with patch.object(server, "run", side_effect=collide), self.assertRaisesRegex(server.SetupError, "already exists"):
            self.install()
        self.assertIn("svc_tunnel", self.accounts)
        self.assertFalse(any(command[0] == "userdel" for command in self.commands))


if __name__ == "__main__":
    unittest.main()
