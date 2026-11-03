"""Token format, storage, and OpenSSH askpass boundaries (no OS changes)."""
import json
import os
from pathlib import Path
import socket
import string
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from profiles import key_profile
from sservcli.askpass import TOKEN_ENV, environment
from sservcli.config import ConfigError, load_profile, token_profile, validate_profile, validate_token
from sservcli.token_auth import TOKEN_ALPHABET, generate_token, remembered_token, store_token
from sservcli.tunnel import Tunnel, ssh_arguments

ROOT = Path(__file__).resolve().parents[1]


class TokenTests(unittest.TestCase):
    def test_tokens_are_exactly_eight_case_sensitive_base62_characters(self):
        self.assertEqual(len(set(TOKEN_ALPHABET)), 62)
        self.assertEqual(set(TOKEN_ALPHABET), set(string.ascii_letters + string.digits))
        for _ in range(100):
            self.assertRegex(generate_token(), r"\A[A-Za-z0-9]{8}\Z")
        for invalid in ("short", "TooLong123", "1234567!", "가나다라마바사아", "abc_defg", "abcdefgh\n", None):
            with self.subTest(invalid=invalid), self.assertRaises(ConfigError):
                validate_token(invalid)
        with patch('sservcli.token_auth.secrets.choice', side_effect=list('A' * 8 + 'b' * 8)):
            self.assertEqual(generate_token('A' * 8), 'b' * 8)

    def test_remembered_tokens_are_separate_from_the_profile_and_can_be_forgotten(self):
        config = load_profile(ROOT / 'examples/services.token.json')
        config['ssh']['host_public_key'] = 'ssh-ed25519 fixture-host-identity'
        with tempfile.TemporaryDirectory() as temporary:
            store_token(temporary, config, 'Ab1Cd2E3')
            self.assertEqual(remembered_token(temporary, config), 'Ab1Cd2E3')
            if os.name == 'nt':
                self.assertNotIn('Ab1Cd2E3', (Path(temporary) / 'tokens.json').read_text())
            else:
                self.assertEqual((Path(temporary) / 'tokens.json').stat().st_mode & 0o777, 0o600)
            other = json.loads(json.dumps(config))
            other['ssh']['port'] = 2222
            self.assertIsNone(remembered_token(temporary, other))
            store_token(temporary, config, None)
            self.assertIsNone(remembered_token(temporary, config))

    def test_token_profile_preserves_native_ssh_user_and_port_but_excludes_credentials(self):
        legacy = key_profile()
        legacy['ssh'].update(user='custom_tunnel', port=2222)
        config = token_profile(legacy)
        self.assertEqual(config['version'], 2)
        self.assertEqual(config['ssh']['port'], 2222)
        self.assertEqual(config['ssh']['user'], 'custom_tunnel')
        self.assertNotIn('identity_file', config['ssh'])
        self.assertEqual(config['services'], legacy['services'])
        for field in ('token', 'identity_file'):
            changed = json.loads(json.dumps(config))
            changed['ssh'][field] = 'Ab1Cd2E3'
            with self.assertRaises(ConfigError):
                validate_profile(changed)

    def test_native_ssh_arguments_use_one_password_prompt_and_all_forwards(self):
        config = load_profile(ROOT / 'examples/services.token.json')
        args = ssh_arguments(config, '/tmp/known hosts')
        self.assertEqual(args.count('-L'), 3)
        self.assertIn('PreferredAuthentications=password', args)
        self.assertIn('PasswordAuthentication=yes', args)
        self.assertIn('PubkeyAuthentication=no', args)
        self.assertIn('NumberOfPasswordPrompts=1', args)
        self.assertIn('StrictHostKeyChecking=yes', args)
        self.assertIn('BatchMode=no', args)
        self.assertNotIn('Ab1Cd2E3', ' '.join(args))

    def test_askpass_uses_only_child_environment_and_preserves_case(self):
        secret = 'Ab1Cd2E3'
        before = dict(os.environ)
        with tempfile.TemporaryDirectory(prefix='sservcli askpass ') as temporary:
            values = environment(secret, temporary)
            self.assertEqual(dict(os.environ), before)
            if os.name == 'nt':
                command = values['SSH_ASKPASS'] + ' "ignored password prompt"'
                options = {'creationflags': subprocess.CREATE_NO_WINDOW}
            else:
                command = [values['SSH_ASKPASS'], 'ignored password prompt']
                options = {}
                self.assertNotIn(secret, Path(values['SSH_ASKPASS']).read_text())
            self.assertNotIn(secret, str(command))
            result = subprocess.run(command, env=values, capture_output=True, timeout=5, **options)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, (secret + '\n').encode())
            values['SSH_ASKPASS_PROMPT'] = 'confirm'
            result = subprocess.run(command, env=values, capture_output=True, timeout=5, **options)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b'')

    def test_token_connection_requires_a_pinned_host_before_spawning_ssh(self):
        config = load_profile(ROOT / 'examples/services.token.json')
        config['ssh'].pop('host_public_key', None)
        with patch('sservcli.tunnel.subprocess.Popen') as spawn:
            with self.assertRaisesRegex(ConfigError, 'public host key'):
                Tunnel().connect(config, token='Ab1Cd2E3')
            spawn.assert_not_called()


if __name__ == '__main__':
    unittest.main()
