#!/usr/bin/env python3
"""A fixed-scope, host-side privilege helper for the Docker server controller."""
import argparse
import contextlib
import fcntl
import json
import os
from pathlib import Path
import select
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from server import sservcli_server as provision
from sservcli.config import ConfigError, load_profile, token_profile
from sservcli.host_bridge import Peer, scope

STATE = Path("/var/lib/sservcli/ssh-bridge")
UNIT = "sservcli-ssh-bridge.service"
SOCKET_DIR = STATE / "ipc"
RUNTIME_FILES = ("server/ssh_bridge.py", "server/sservcli_server.py", "sservcli/__init__.py",
                 "sservcli/config.py", "sservcli/token_auth.py", "sservcli/host_bridge.py")


def unit_text(state=STATE):
    return f"""[Unit]
Description=sservcli host SSH privilege helper
After=network.target
Before=docker.service

[Service]
Type=simple
ExecStartPre=/usr/bin/python3 {state}/runtime/server/ssh_bridge.py cleanup --state-dir {state}
ExecStart=/usr/bin/python3 {state}/runtime/server/ssh_bridge.py serve --state-dir {state}
ExecStopPost=/usr/bin/python3 {state}/runtime/server/ssh_bridge.py cleanup --state-dir {state}
Restart=on-failure
RestartSec=2
KillMode=mixed
TimeoutStopSec=45
UMask=0077

[Install]
WantedBy=multi-user.target
"""


def install(args):
    profile = token_profile(load_profile(args.config))
    provision.username(profile["ssh"]["user"])
    provision.destinations(scope(profile)["destinations"])
    # Only public connection metadata and a fixed authorization scope are saved.
    # Container requests cannot choose a command, account or destination list.
    snapshot = {"profile": profile, "sshd_config": str(Path(args.sshd_config).resolve()),
                "ssh_service": args.ssh_service, "host_key": str(Path(args.host_key).resolve()),
                "sshd_pid_file": args.sshd_pid_file}
    provision.safe_file(Path(args.sshd_config))
    unit = Path("/etc/systemd/system") / UNIT
    if unit.exists():
        # Revoke the old approved account before replacing its configuration.
        provision.run(["systemctl", "stop", UNIT])
    provision.ensure_state_dir(STATE.parent)
    provision.ensure_state_dir(STATE)
    provision.ensure_state_dir(SOCKET_DIR)
    runtime = STATE / "runtime"
    provision.ensure_state_dir(runtime)
    for name in RUNTIME_FILES:
        source = ROOT / name
        if source.is_symlink() or not source.is_file() or source.stat().st_size > 1024 * 1024:
            raise ConfigError("Invalid host helper source file")
        target = runtime / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        provision.atomic_write(target, source.read_text(), mode=0o600)
    provision.atomic_write(STATE / "config.json", json.dumps(snapshot, indent=2) + "\n")
    provision.atomic_write(unit, unit_text(STATE), mode=0o644)
    provision.run(["systemctl", "daemon-reload"])
    provision.run(["systemctl", "enable", UNIT])
    provision.run(["systemctl", "restart", UNIT])
    print(f"Host SSH helper installed; approved SSH port: {profile['ssh']['port']}; socket: {SOCKET_DIR / 'bridge.sock'}")


def load_snapshot(state):
    provision.safe_directory(state)
    path = state / "config.json"
    provision.safe_file(path)
    value = json.loads(path.read_text())
    value["profile"] = token_profile(value["profile"])
    return value


class BridgeServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = False
    block_on_close = True

    def __init__(self, path, snapshot, state, *, factory=None, request_timeout=60):
        self.snapshot, self.state = snapshot, Path(state)
        self.authorized_scope = scope(snapshot["profile"])
        self.factory = factory
        self.request_timeout = request_timeout
        self.lease_lock = threading.Lock()
        self.lock = threading.Lock()
        self.connections, self.children = set(), set()
        self.active_id = None
        self.stopping = False
        super().__init__(str(path), BridgeHandler)
        os.chmod(path, 0o600)

    def helper(self, operation):
        if self.factory:
            return self.factory(operation)
        command = [sys.executable, str(ROOT / "server/sservcli_server.py"), operation,
                   "--config", str(self.state / "profile.json"), "--sshd-config", self.snapshot["sshd_config"],
                   "--ssh-service", self.snapshot["ssh_service"], "--host-key", self.snapshot["host_key"], "--ensure-ssh"]
        if self.snapshot.get("sshd_pid_file"):
            command += ["--sshd-pid-file", self.snapshot["sshd_pid_file"]]
        return subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    def launch(self, operation):
        child = self.helper(operation)
        with self.lock:
            self.children.add(child)
        return child

    def finish(self, child):
        try:
            if child.stdin:
                child.stdin.close()
            try:
                result = child.wait(timeout=30)
            except subprocess.TimeoutExpired:
                child.terminate()
                result = child.wait(timeout=10)
            if result:
                raise ConfigError("Host SSH setup or token revocation failed; inspect the host helper journal")
        finally:
            if child.stdout:
                child.stdout.close()
            with self.lock:
                self.children.discard(child)

    def receipt(self, child):
        if not select.select([child.stdout], [], [], 30)[0]:
            child.terminate()
            raise ConfigError("Host SSH helper timed out")
        line = child.stdout.readline(32769)
        if not line or len(line) > 32768 or not line.endswith("\n"):
            raise ConfigError("Host SSH helper failed; inspect journalctl -u sservcli-ssh-bridge")
        try:
            receipt = json.loads(line)
        except ValueError as error:
            raise ConfigError("Invalid host SSH helper receipt") from error
        if not isinstance(receipt, dict):
            raise ConfigError("Invalid host SSH helper receipt")
        return receipt

    def close_clients(self):
        with self.lock:
            self.stopping = True
            connections, children = list(self.connections), list(self.children)
        for connection in connections:
            with contextlib.suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)
        for child in children:
            if child.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    child.terminate()


class BridgeHandler(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server
        with server.lock:
            if server.stopping:
                return
            server.connections.add(self.request)
        peer = Peer(self.request)
        child = None
        leased = False
        self.request.settimeout(server.request_timeout)
        try:
            request = peer.receive()
            if set(request) != {"operation", "scope"} or request["scope"] != server.authorized_scope:
                raise ConfigError("The requested SSH account/ports differ from the approved host profile; rerun make docker-up")
            operation = request["operation"]
            if operation == "ping":
                with server.lock:
                    active = server.active_id
                peer.send({"ok": True, "lease_id": active, "ssh_port": server.authorized_scope["ssh_port"]})
            elif operation == "prepare":
                child = server.launch("token-prepare")
                receipt = server.receipt(child)
                server.finish(child)
                child = None
                peer.send({"ok": True, "receipt": receipt})
            elif operation == "lease":
                leased = server.lease_lock.acquire(blocking=False)
                if not leased:
                    raise ConfigError("A Docker server already owns the host SSH token lease")
                child = server.launch("token-serve")
                receipt = server.receipt(child)
                lease_id = uuid.uuid4().hex
                with server.lock:
                    server.active_id = lease_id
                peer.send({"ok": True, "receipt": receipt, "lease_id": lease_id})
                while True:
                    message = peer.receive()
                    if message == {"operation": "release"}:
                        server.finish(child)
                        child = None
                        peer.send({"ok": True})
                        break
                    if message != {"operation": "heartbeat"} or child.poll() is not None:
                        raise ConfigError("Host SSH token lease ended")
                    peer.send({"ok": True, "lease_id": lease_id})
            else:
                raise ConfigError("Unsupported host SSH bridge operation")
        except (OSError, ConfigError, ValueError, subprocess.SubprocessError) as error:
            with contextlib.suppress(OSError, ConfigError):
                peer.send({"error": str(error) or "Host SSH bridge request failed"})
        finally:
            try:
                if child:
                    server.finish(child)
            except (OSError, ConfigError, subprocess.SubprocessError) as error:
                print(f"Host token cleanup failed: {error}", file=sys.stderr, flush=True)
            finally:
                if leased:
                    with server.lock:
                        server.active_id = None
                    server.lease_lock.release()
                with server.lock:
                    server.connections.discard(self.request)
                peer.close()


def serve(state):
    snapshot = load_snapshot(state)
    provision.ensure_state_dir(state / "ipc")
    provision.atomic_write(state / "profile.json", json.dumps(snapshot["profile"]) + "\n")
    path = state / "ipc/bridge.sock"
    path.unlink(missing_ok=True)
    stopping = threading.Event()
    previous = {number: signal.signal(number, lambda *_: stopping.set()) for number in (signal.SIGTERM, signal.SIGINT)}
    server = BridgeServer(path, snapshot, state)
    worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1})
    worker.start()
    try:
        stopping.wait()
    finally:
        server.shutdown()
        server.close_clients()
        server.server_close()
        worker.join()
        path.unlink(missing_ok=True)
        for number, handler in previous.items():
            signal.signal(number, handler)


def cleanup(state):
    snapshot = load_snapshot(state)
    args = argparse.Namespace(sshd_config=snapshot["sshd_config"], ssh_service=snapshot["ssh_service"],
                              sshd_pid_file=snapshot.get("sshd_pid_file"), client_address="127.0.0.1")
    manager = provision.Provisioner(args)
    with provision.management_lock():
        user = manager.resolve_token_user(snapshot["profile"]["ssh"]["user"])
        if not manager.state_path(user).exists():
            return
        with open(f"/run/lock/sservcli-token-{user}.lock", "a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return  # Another live controller owns this account now.
            record, entry, _ = manager.managed_identity(user)
            if record.get("auth_mode") == "token":
                manager.lock_token(user, entry.pw_uid)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    install_parser = sub.add_parser("install")
    install_parser.add_argument("--config", type=Path, required=True)
    install_parser.add_argument("--sshd-config", default="/etc/ssh/sshd_config")
    install_parser.add_argument("--ssh-service", default="ssh")
    install_parser.add_argument("--host-key", default=os.environ.get("HOST_KEY_FILE") or "/etc/ssh/ssh_host_ed25519_key.pub")
    install_parser.add_argument("--sshd-pid-file", default=None)
    for operation in ("serve", "cleanup"):
        command = sub.add_parser(operation)
        command.add_argument("--state-dir", type=Path, default=STATE)
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            if args.command == "install":
                command = ["sudo", sys.executable, str(Path(__file__).resolve()), "install",
                           "--config", str(args.config.resolve()), "--sshd-config", args.sshd_config,
                           "--ssh-service", args.ssh_service, "--host-key", args.host_key]
                if args.sshd_pid_file:
                    command += ["--sshd-pid-file", args.sshd_pid_file]
                return subprocess.run(command).returncode
            raise ConfigError("Run the host SSH helper as root")
        if args.command == "install":
            install(args)
        elif args.command == "serve":
            serve(args.state_dir)
        else:
            cleanup(args.state_dir)
        return 0
    except (OSError, ValueError, ConfigError, provision.SetupError, subprocess.SubprocessError) as error:
        print(f"sservcli-host-bridge: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
