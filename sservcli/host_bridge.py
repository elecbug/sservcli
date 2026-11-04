"""Bounded local IPC for the container controller and the host SSH helper."""
import json
from pathlib import Path
import socket

from .config import ConfigError, token_profile, validate_token

MAX_MESSAGE = 32768


def scope(config):
    profile = token_profile(config)
    return {"user": profile["ssh"]["user"], "ssh_port": profile["ssh"]["port"],
            "destinations": sorted({f"127.0.0.1:{service['remote_port']}" for service in profile["services"]})}


class Peer:
    def __init__(self, connection):
        self.connection = connection
        self.stream = connection.makefile("rwb")

    def send(self, message):
        data = json.dumps(message, separators=(",", ":")).encode() + b"\n"
        if len(data) > MAX_MESSAGE:
            raise ConfigError("Host SSH bridge message is too large")
        self.stream.write(data)
        self.stream.flush()

    def receive(self):
        line = self.stream.readline(MAX_MESSAGE + 1)
        if not line or len(line) > MAX_MESSAGE or not line.endswith(b"\n"):
            raise ConfigError("Host SSH bridge connection ended or returned an invalid message")
        try:
            message = json.loads(line)
        except (ValueError, UnicodeError) as error:
            raise ConfigError("Invalid host SSH bridge response") from error
        if not isinstance(message, dict):
            raise ConfigError("Invalid host SSH bridge response")
        return message

    def close(self):
        try:
            self.stream.close()
        except OSError:
            pass  # A disconnected peer may have left buffered error output.
        finally:
            self.connection.close()


def connect(path, timeout=35):
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(timeout)
    try:
        connection.connect(str(path))
        return Peer(connection)
    except BaseException:
        connection.close()
        raise


def response(peer):
    message = peer.receive()
    if "error" in message:
        raise ConfigError(str(message["error"]))
    if message.get("ok") is not True:
        raise ConfigError("Host SSH bridge rejected the request")
    return message


def request(path, operation, config):
    peer = connect(path)
    try:
        peer.send({"operation": operation, "scope": scope(config)})
        return response(peer)
    finally:
        peer.close()


class Lease:
    def __init__(self, path, config, *, reuse_token=None, no_reset_token=False):
        self.path, self.config = Path(path), config
        self.peer = None
        self.receipt = self.lease_id = None
        self.reuse_token = validate_token(reuse_token) if reuse_token is not None else None
        self.no_reset_token = no_reset_token or reuse_token is not None

    def start(self):
        self.peer = connect(self.path)
        try:
            message = {"operation": "lease", "scope": scope(self.config)}
            if self.no_reset_token:
                message["reuse_token"] = self.reuse_token
            self.peer.send(message)
            message = response(self.peer)
            self.receipt, self.lease_id = message["receipt"], message["lease_id"]
            if not isinstance(self.receipt, dict) or not isinstance(self.lease_id, str):
                raise ConfigError("Invalid host SSH lease")
            return self
        except BaseException:
            self.close()
            raise

    def heartbeat(self):
        self.peer.send({"operation": "heartbeat"})
        message = response(self.peer)
        if message.get("lease_id") != self.lease_id:
            raise ConfigError("Host SSH token lease changed")

    def close(self):
        if self.peer:
            peer, self.peer = self.peer, None
            try:
                peer.send({"operation": "release"})
                response(peer)
            except (OSError, ConfigError):
                # Closing the socket also causes the host to revoke the lease.
                pass
            finally:
                peer.close()
