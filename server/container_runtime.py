#!/usr/bin/env python3
"""Run a private OpenSSH daemon and token controller inside the server container."""
from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from server import sservcli_server as provision
from sservcli.config import ConfigError, load_profile, token_profile
from sservcli.token_auth import FileLock, private_directory, write_private
from sservcli.token_server import TokenServer


@dataclass(frozen=True)
class Settings:
    config: Path
    state: Path
    sshd_config: Path
    pid_file: Path
    public_key: Path
    port: int
    address: str

    @property
    def ready_file(self):
        return self.pid_file.parent / "ready.json"


def settings():
    env = os.environ
    value = env.get("SSERVCLI_SSH_PORT", "2222")
    if not value.isascii() or not value.isdigit() or not 1 <= int(value) <= 65535:
        raise ConfigError("SSERVCLI_SSH_PORT must be an integer from 1 to 65535")
    address = env.get("SSERVCLI_LISTEN_ADDRESS", "0.0.0.0")
    ipaddress.ip_address(address)
    result = Settings(
        Path(env.get("CONFIG") or "/config/services.json"),
        Path(env.get("SERVER_STATE") or "/state"),
        Path(env.get("SSHD_CONFIG") or "/etc/ssh/sshd_config"),
        Path(env.get("SSHD_PID_FILE") or "/run/sservcli/sshd.pid"),
        Path(env.get("HOST_KEY_FILE") or "/state/ssh_host_ed25519.pub"),
        int(value), address,
    )
    if result.public_key.suffix != ".pub":
        raise ConfigError("HOST_KEY_FILE must name a public .pub file")
    return result


def prepare_state(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not path.is_dir() or path.is_symlink():
        raise ConfigError("Docker state must be a real directory")
    # This dedicated bind mount is root-owned inside the container. It is
    # deliberately separate from the native server's var/server state.
    if info.st_uid != 0:
        os.chown(path, 0, 0)
    path.chmod(0o700)
    return private_directory(path)


def prepare_host_key(public):
    key = public.with_suffix("")
    private_directory(key.parent)
    if not os.path.lexists(key):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    provision.safe_file(key)
    key.chmod(0o600)
    # Re-derive the public half so stale public files cannot pin a different key.
    result = subprocess.run(["ssh-keygen", "-y", "-f", str(key)], capture_output=True, text=True, check=True)
    provision.atomic_write(public, result.stdout.strip() + "\n", mode=0o644)


def bootstrap(options, profile):
    options.pid_file.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    runtime_root = options.pid_file.parent.parent
    (runtime_root / "sshd").mkdir(mode=0o755, parents=True, exist_ok=True)
    (runtime_root / "lock").mkdir(mode=0o755, parents=True, exist_ok=True)
    provision.atomic_write(options.pid_file.parent / "listen.conf",
                           f"Port {options.port}\nListenAddress {options.address}\n")
    args = SimpleNamespace(sshd_config=str(options.sshd_config), ssh_service="ssh",
                           sshd_pid_file=str(options.pid_file), client_address="127.0.0.1")
    manager = provision.Provisioner(args)
    permitted = provision.destinations([f"127.0.0.1:{service['remote_port']}" for service in profile["services"]])
    with provision.management_lock():
        user = manager.resolve_token_user(profile["ssh"]["user"])
        # Apply the complete restrictive policy before opening the SSH socket.
        receipt = manager.ensure_token(user, permitted, activate=False)
        manager.lock_token(user, receipt["uid"])
    return manager


def wait_for_daemon(process, manager, stopping, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if stopping.is_set():
            return False
        if process.poll() is not None:
            raise ConfigError("Container sshd exited; check its logs and whether the SSH port is occupied")
        try:
            if manager.daemon_pid() == process.pid:
                return True
        except (OSError, provision.SetupError):
            pass
        stopping.wait(0.05)
    raise ConfigError("Container sshd did not publish its PID file")


def stop_daemon(process):
    if process and process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)


def serve():
    if os.geteuid() != 0 or not Path("/.dockerenv").is_file():
        raise ConfigError("Use this entry point as root inside the server Docker container")
    options = settings()
    profile = token_profile(load_profile(options.config), options.port)
    prepare_state(options.state)
    stopping = threading.Event()
    previous = {number: signal.signal(number, lambda *_: stopping.set())
                for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    try:
        with FileLock(options.state / "container.lock"):
            master = controller = None
            try:
                options.ready_file.unlink(missing_ok=True)
                prepare_host_key(options.public_key)
                manager = bootstrap(options, profile)
                if stopping.is_set():
                    return 0
                master = subprocess.Popen([manager.sshd, "-D", "-e", "-f", str(options.sshd_config)], start_new_session=True)
                if not wait_for_daemon(master, manager, stopping):
                    return 0
                controller = TokenServer(profile, options.state, sshd_config=options.sshd_config,
                                         sshd_pid_file=options.pid_file, host_key=options.public_key)
                controller.start()
                write_private(options.ready_file, json.dumps({"sshd_pid": master.pid, "controller_pid": os.getpid(),
                                                             "helper_pid": controller.process.pid, "port": options.port}))
                print(f"OpenSSH container ready on {options.address}:{options.port}; account: {controller.user}", flush=True)
                print(f"Current token stored in {options.state / 'access.token'}. Use docker-bundle to download the Windows client.", flush=True)
                while not stopping.wait(0.2):
                    if master.poll() is not None or controller.process.poll() is not None:
                        raise ConfigError("Container SSH/token process stopped unexpectedly")
                return 0
            finally:
                options.ready_file.unlink(missing_ok=True)
                try:
                    if controller:
                        controller.close()
                finally:
                    stop_daemon(master)
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def healthcheck(options=None):
    try:
        options = options or settings()
        info = json.loads(options.ready_file.read_text())
        for field in ("sshd_pid", "controller_pid", "helper_pid"):
            pid = info[field]
            if type(pid) is not int or pid <= 1:
                return False
            os.kill(pid, 0)
        return info["port"] == options.port
    except (OSError, ValueError, KeyError, TypeError):
        return False


def bundle(argv):
    from tools import bundle_windows
    options = settings()
    if not healthcheck(options):
        raise ConfigError("Start the Compose server and wait for it to be healthy before bundling")
    args = bundle_windows.parser().parse_args(argv)
    args.config, args.state_dir = options.config, options.state
    args.token_port, args.host_key = options.port, options.public_key
    args.sshd_config, args.sshd_pid_file = str(options.sshd_config), str(options.pid_file)
    # A CLI argument or Compose's /dist output controls publication, not /opt.
    if args.output is None:
        args.output = Path("/dist/sservcli-windows-token.zip")
    owner = [os.environ.get(field) for field in ("BUNDLE_UID", "BUNDLE_GID")]
    if any(value is not None for value in owner) and not all(value and value.isascii() and value.isdigit() and int(value) <= 2**31 - 1 for value in owner):
        raise ConfigError("Set both BUNDLE_UID and BUNDLE_GID to numeric host IDs")
    output = bundle_windows.package(args)
    if output and owner[0] is not None:
        os.chown(output, int(owner[0]), int(owner[1]))
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    command = argv.pop(0) if argv else "serve"
    try:
        if command == "serve" and not argv:
            return serve()
        if command == "healthcheck" and not argv:
            return 0 if healthcheck() else 1
        if command == "bundle":
            return bundle(argv)
        raise ConfigError("Use serve, healthcheck, or bundle")
    except (ConfigError, provision.SetupError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"sservcli-container: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
