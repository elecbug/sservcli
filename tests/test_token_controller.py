"""Controller lifetime tests; the sudo/account helper is mocked, never run."""
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sservcli.config import ConfigError, load_profile
from sservcli.token_auth import read_private
from sservcli.token_server import TokenServer

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == "posix", "The account controller runs on Ubuntu")
class TokenControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.profile = load_profile(ROOT / "examples/services.token.json")
        self.receipt = {"token": "Ab1Cd2E3", "user": "svc_tunnel_token1", "requested_user": "svc_tunnel",
                        "host_public_key": "ssh-ed25519 AAAAAAAAAAAAAAAA", "permitted": ["127.0.0.1:8080"]}
        self.stdin = io.StringIO()
        self.process = SimpleNamespace(stdin=self.stdin, stdout=io.StringIO(json.dumps(self.receipt) + "\n"),
                                       poll=Mock(return_value=None), wait=Mock(return_value=0))
        self.controller = TokenServer(self.profile, self.directory / "state")
        self.addCleanup(self.controller.close)

    def test_start_publishes_only_public_metadata_and_close_signals_pipe_eof(self):
        with patch("sservcli.token_server.subprocess.run") as authorize, patch("sservcli.token_server.subprocess.Popen", return_value=self.process) as start:
            self.controller.start()
        command = start.call_args.args[0]
        self.assertIn("token-serve", command)
        self.assertNotIn(self.receipt["token"], str(command))
        self.assertFalse(start.call_args.kwargs.get("start_new_session", False))
        self.assertEqual(read_private(self.directory / "state/access.token").strip(), self.receipt["token"])
        metadata = read_private(self.directory / "state/server.json")
        self.assertNotIn(self.receipt["token"], metadata)
        self.assertEqual(json.loads(metadata)["user"], "svc_tunnel_token1")
        self.controller.close()
        self.assertTrue(self.stdin.closed)
        self.process.wait.assert_called_once()

    def test_failed_local_publication_closes_the_helper_control_pipe(self):
        from sservcli.token_server import write_private
        def fail_token(path, text):
            if Path(path).name == "access.token":
                raise OSError("fixture storage failure")
            return write_private(path, text)
        with (patch("sservcli.token_server.subprocess.run"),
              patch("sservcli.token_server.subprocess.Popen", return_value=self.process),
              patch("sservcli.token_server.write_private", side_effect=fail_token)):
            with self.assertRaisesRegex(OSError, "storage failure"):
                self.controller.start()
        self.assertTrue(self.stdin.closed)
        self.assertIsNone(self.controller.state_lock)

    def test_a_failed_helper_does_not_publish_a_usable_token(self):
        self.process.stdout = io.StringIO("")
        self.process.wait.return_value = 1
        with patch("sservcli.token_server.subprocess.run"), patch("sservcli.token_server.subprocess.Popen", return_value=self.process):
            with self.assertRaises(ConfigError):
                self.controller.start()
        self.assertFalse((self.directory / "state/access.token").exists())
        self.assertTrue(self.stdin.closed)
