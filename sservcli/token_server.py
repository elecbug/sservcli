"""Unprivileged token controller for the system's existing OpenSSH daemon."""
import json
import os
from pathlib import Path
import subprocess
import sys
import threading

from .config import ConfigError, token_profile, validate_token
from .token_auth import FileLock, private_directory, write_private

ROOT = Path(__file__).resolve().parents[1]


class TokenServer:
    def __init__(self, config, state_dir, *, sshd_config="/etc/ssh/sshd_config", ssh_service="ssh",
                 host_key="/etc/ssh/ssh_host_ed25519_key.pub", sshd_pid_file=None):
        self.profile = token_profile(config)
        self.state_dir = private_directory(state_dir)
        self.sshd_config, self.ssh_service, self.host_key = sshd_config, ssh_service, host_key
        self.sshd_pid_file = sshd_pid_file
        self.stopping = threading.Event()
        self.process = self.state_lock = None
        self.token = self.public_key = self.user = None

    def start(self):
        if self.process:
            raise ConfigError("Token controller is already running")
        self.state_lock = FileLock(self.state_dir / "controller.lock")
        self.state_lock.__enter__()
        try:
            policy = self.state_dir / "controller-profile.json"
            write_private(policy, json.dumps(self.profile))
            command = [sys.executable, str(ROOT / "server/sservcli_server.py"), "token-serve", "--config", str(policy),
                       "--sshd-config", str(self.sshd_config), "--ssh-service", self.ssh_service,
                       "--host-key", str(self.host_key), "--ensure-ssh"]
            if self.sshd_pid_file:
                command += ["--sshd-pid-file", str(self.sshd_pid_file)]
            if os.name == "nt":
                raise ConfigError("Run the server token controller on Ubuntu/OpenSSH")
            if os.geteuid() != 0:
                # Keep the caller's terminal/session so sudo -n can use the
                # same timestamp as sudo -v. Its stdin remains the lifetime
                # pipe; sudo never reads a password from that pipe.
                subprocess.run(["sudo", "-v"], check=True)
                command = ["sudo", "-n", *command]
            self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            text=True, encoding="utf-8")
            line = self.process.stdout.readline(32769)
            if not line or len(line) > 32768 or not line.endswith("\n"):
                raise ConfigError("OpenSSH account setup failed; see the administrator error above")
            receipt = json.loads(line)
            if not isinstance(receipt, dict) or not all(isinstance(receipt.get(field), str) for field in ("token", "user", "host_public_key", "requested_user")) or not isinstance(receipt.get("permitted"), list):
                raise ConfigError("Invalid OpenSSH setup response")
            self.token = validate_token(receipt["token"])
            self.user, self.public_key = receipt["user"], receipt["host_public_key"]
            if not isinstance(self.user, str) or not isinstance(self.public_key, str):
                raise ConfigError("Invalid OpenSSH setup response")
            self.profile["ssh"].update(user=self.user, host_public_key=self.public_key)
            # Publish no credential in the metadata used for Windows packaging.
            metadata = {"requested_user": receipt["requested_user"], "user": self.user,
                        "host_public_key": self.public_key, "permitted": receipt["permitted"],
                        "sshd_config": str(self.sshd_config)}
            write_private(self.state_dir / "server.json", json.dumps(metadata, indent=2) + "\n")
            write_private(self.state_dir / "access.token", self.token + "\n")
            return self
        except BaseException:
            self.close()
            raise

    def close(self):
        self.stopping.set()
        try:
            if self.process:
                process, self.process = self.process, None
                if process.stdin:
                    process.stdin.close()
                result = process.wait(timeout=30)
                if process.stdout:
                    process.stdout.close()
                if result:
                    raise ConfigError("OpenSSH token setup/revocation failed; inspect the administrator error output")
        finally:
            if self.state_lock:
                self.state_lock.__exit__(None, None, None)
                self.state_lock = None
