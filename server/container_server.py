#!/usr/bin/env python3
"""Docker token controller; SSH transport remains in the host's existing sshd."""
import argparse
import hmac
import json
import os
from pathlib import Path
import signal
import stat
import sys
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sservcli.config import ConfigError, load_profile, token_profile, validate_profile, validate_token
from sservcli.host_bridge import Lease, request
from sservcli.token_auth import FileLock, private_directory, read_private, write_private


def container_state(path):
    """Secure only the dedicated container state mount, never native host state."""
    path = Path(path).absolute()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise ConfigError("Container state must be a real directory")
    if os.geteuid() == 0:
        os.chown(path, 0, 0)
        path.chmod(0o700)
    return private_directory(path)


class Controller:
    def __init__(self, config, state, bridge, *, no_reset_token=False):
        self.profile = token_profile(config)
        self.state, self.bridge = container_state(state), Path(bridge)
        self.lease = self.lock = None
        self.no_reset_token = no_reset_token

    def start(self):
        lock = FileLock(self.state / "controller.lock")
        lock.__enter__()
        self.lock = lock
        try:
            (self.state / "ready.json").unlink(missing_ok=True)
            existing = None
            token_path = self.state / "access.token"
            if self.no_reset_token and os.path.lexists(token_path):
                existing = validate_token(read_private(token_path).rstrip("\r\n"))
            self.lease = Lease(self.bridge, self.profile, reuse_token=existing, no_reset_token=self.no_reset_token).start()
            receipt = self.lease.receipt
            if (receipt.get("requested_user") != self.profile["ssh"]["user"]
                    or not isinstance(receipt.get("user"), str)
                    or not isinstance(receipt.get("host_public_key"), str)):
                raise ConfigError("Invalid host SSH setup response")
            token = validate_token(receipt.get("token"))
            if existing is not None and (not hmac.compare_digest(token, existing) or receipt.get("token_reused") is not True):
                raise ConfigError("The host did not preserve the saved token; private token state was not overwritten")
            final = token_profile(self.profile)
            final["ssh"].update(user=receipt["user"], host_public_key=receipt["host_public_key"])
            validate_profile(final)
            write_private(self.state / "server.json", json.dumps({
                "user": receipt["user"], "requested_user": receipt["requested_user"],
                "host_public_key": receipt["host_public_key"], "ssh_port": final["ssh"]["port"]}) + "\n")
            write_private(self.state / "access.token", token + "\n")
            write_private(self.state / "ready.json", json.dumps({"pid": os.getpid(), "lease_id": self.lease.lease_id}) + "\n")
            return self
        except BaseException:
            self.close()
            raise

    def close(self):
        try:
            if self.lock:
                (self.state / "ready.json").unlink(missing_ok=True)
            if self.lease:
                lease, self.lease = self.lease, None
                lease.close()  # The host acknowledges only after token revocation.
        finally:
            if self.lock:
                self.lock.__exit__(None, None, None)
                self.lock = None


def healthcheck(config, state, bridge):
    ready = json.loads(read_private(Path(state) / "ready.json"))
    if type(ready.get("pid")) is not int or ready["pid"] <= 0:
        raise ConfigError("The Docker server is not running")
    os.kill(ready["pid"], 0)
    active = request(bridge, "ping", config)
    if not ready.get("lease_id") or active.get("lease_id") != ready["lease_id"]:
        raise ConfigError("The Docker server no longer owns the host SSH token")


def serve(config, state, bridge, *, no_reset_token=False):
    stopping = threading.Event()
    previous = {number: signal.signal(number, lambda *_: stopping.set()) for number in (signal.SIGTERM, signal.SIGINT)}
    controller = Controller(config, state, bridge, no_reset_token=no_reset_token)
    try:
        controller.start()
        action = "Reused saved token" if controller.lease.receipt.get("token_reused") else "Issued new token"
        print(f"Docker server ready; using existing host SSH port {controller.profile['ssh']['port']}. {action}; saved privately in /state/access.token.", flush=True)
        while not stopping.wait(5):
            controller.lease.heartbeat()
    finally:
        controller.close()
        for number, handler in previous.items():
            signal.signal(number, handler)


def package(config, state, bridge):
    from tools import bundle_windows as bundle
    owner = [os.environ.get(field, "") for field in ("BUNDLE_UID", "BUNDLE_GID")]
    if not all(value.isascii() and value.isdigit() and int(value) <= 2**31 - 1 for value in owner):
        raise ConfigError("BUNDLE_UID and BUNDLE_GID must identify the host user")
    args = bundle.parser().parse_args([])
    args.config, args.state_dir, args.bridge_socket = Path(config), Path(state), Path(bridge)
    args.output = Path(os.environ.get("BUNDLE_OUTPUT") or "/dist/sservcli-windows-token.zip")
    args.client_only, args.legacy_ssh, args.token_port, args.token_file = False, False, None, None
    if not args.dry_run:
        healthcheck(load_profile(config), state, bridge)
    output = bundle.package(args)
    if output:
        os.chown(output, int(owner[0]), int(owner[1]))
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    if os.environ.get("NO_RESET_TOKEN", "0") not in ("0", "1"):
        parser.error("NO_RESET_TOKEN must be 0 or 1")
    parser.add_argument("command", choices=("serve", "healthcheck", "bundle"))
    parser.add_argument("--config", type=Path, default=Path(os.environ.get("CONFIG") or "/config/services.json"))
    parser.add_argument("--state-dir", type=Path, default=Path(os.environ.get("SERVER_STATE") or "/state"))
    parser.add_argument("--bridge-socket", type=Path, default=Path(os.environ.get("SSERVCLI_BRIDGE_SOCKET") or "/host-ssh/bridge.sock"))
    parser.add_argument("--no-reset-token", action="store_true", default=os.environ.get("NO_RESET_TOKEN") == "1",
                        help="Reuse the private saved token when it matches the managed SSH account")
    args = parser.parse_args(argv)
    try:
        if args.command == "bundle":
            package(args.config, args.state_dir, args.bridge_socket)
        else:
            config = load_profile(args.config)
            if args.command == "serve":
                serve(config, args.state_dir, args.bridge_socket, no_reset_token=args.no_reset_token)
            else:
                healthcheck(config, args.state_dir, args.bridge_socket)
        return 0
    except (OSError, ValueError, KeyError) as error:
        print(f"sservcli-container: {error}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
