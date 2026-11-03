"""Unprivileged SSH server accepting startup tokens and loopback forwards only."""
from collections import OrderedDict, deque
import hmac
import ipaddress
import logging
import socket
import threading
import time

import paramiko

from .config import ConfigError, token_profile
from .relay import close_stream, relay
from .token_auth import FileLock, generate_token, host_identity, private_directory, read_private, write_private

logging.getLogger("sservcli.ssh").addHandler(logging.NullHandler())
logging.getLogger("sservcli.ssh").propagate = False


class TokenAuthority:
    def __init__(self, token, *, window=60, per_ip=5, total=50, clock=time.monotonic):
        self._token = token.encode("ascii")
        self.window, self.per_ip, self.total, self.clock = window, per_ip, total, clock
        self.failures = OrderedDict()
        self.global_failures = deque()
        self.lock = threading.Lock()

    def _recent(self, peer):
        cutoff = self.clock() - self.window
        while self.global_failures and self.global_failures[0] <= cutoff:
            self.global_failures.popleft()
        failures = self.failures.setdefault(peer, deque())
        self.failures.move_to_end(peer)
        while failures and failures[0] <= cutoff:
            failures.popleft()
        while len(self.failures) > 4096:
            self.failures.popitem(last=False)
        return failures

    def blocked(self, peer):
        with self.lock:
            failures = self._recent(peer)
            return len(failures) >= self.per_ip or len(self.global_failures) >= self.total

    def authenticate(self, peer, username, token):
        with self.lock:
            failures = self._recent(peer)
            if len(failures) >= self.per_ip or len(self.global_failures) >= self.total:
                return False
            supplied = token.encode("utf-8") if isinstance(token, str) and len(token) <= 128 else b""
            correct = hmac.compare_digest(self._token, supplied)
            if correct and username == "sservcli":
                return True
            now = self.clock()
            failures.append(now)
            self.global_failures.append(now)
            return False


class ForwardingInterface(paramiko.ServerInterface):
    def __init__(self, owner, peer):
        self.owner, self.peer = owner, peer
        self.authenticated = False
        self.destinations = {}
        self.lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(64)

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        if self.owner.authority.authenticate(self.peer, username, password):
            self.authenticated = True
            with self.owner.lock:
                self.owner.authentications += 1
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        if not self.authenticated or destination not in self.owner.allowed:
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        if not self.slots.acquire(blocking=False):
            return paramiko.OPEN_FAILED_RESOURCE_SHORTAGE
        if not self.owner.channel_slots.acquire(blocking=False):
            self.slots.release()
            return paramiko.OPEN_FAILED_RESOURCE_SHORTAGE
        with self.lock:
            self.destinations[chanid] = destination
        return paramiko.OPEN_SUCCEEDED

    def check_global_request(self, kind, msg):
        return self.authenticated and kind in ("keepalive@sservcli", "keepalive@openssh.com")

    # All session, shell/exec/SFTP, remote forwarding, agent, X11, and unknown
    # channel requests retain ServerInterface's rejecting defaults.


class TokenServer:
    def __init__(self, config, state_dir, *, listen="0.0.0.0", port=None):
        self.profile = token_profile(config)
        self.state_dir = private_directory(state_dir)
        self.host_key, self.public_key = host_identity(self.state_dir)
        self.listen = str(ipaddress.ip_address(listen))
        self.port = self.profile["ssh"].get("port", 8022) if port is None else port
        self.allowed = {("127.0.0.1", service["remote_port"]) for service in self.profile["services"]}
        self.stopping = threading.Event()
        self.lock = threading.Lock()
        self.connections = set()
        self.transports = set()
        self.sessions = set()
        self.connection_slots = threading.BoundedSemaphore(64)
        self.channel_slots = threading.BoundedSemaphore(256)
        self.listener = None
        self.thread = None
        self.state_lock = None
        self.token = None
        self.authentications = 0
        self.address = None

    def start(self):
        if self.thread and self.thread.is_alive():
            raise ConfigError("This server is already running")
        self.state_lock = FileLock(self.state_dir / "server.lock")
        self.state_lock.__enter__()
        try:
            self.listener = socket.socket(socket.AF_INET6 if ":" in self.listen else socket.AF_INET)
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            else:
                self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener.bind((self.listen, self.port))
            self.listener.listen(64)
            self.listener.settimeout(0.3)
            self.address = self.listener.getsockname()
            previous = None
            token_file = self.state_dir / "access.token"
            if token_file.exists():
                previous = read_private(token_file).strip()
            self.token = generate_token(previous)
            self.authority = TokenAuthority(self.token)
            write_private(token_file, self.token + "\n")
            self.thread = threading.Thread(target=self._accept, daemon=True)
            self.thread.start()
            return self
        except BaseException:
            self.close()
            raise

    def _accept(self):
        while not self.stopping.is_set():
            try:
                connection, address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if self.authority.blocked(address[0]):
                connection.close()
                continue
            if not self.connection_slots.acquire(blocking=False):
                connection.close()
                continue
            worker = threading.Thread(target=self._session, args=(connection, address[0]), daemon=True)
            with self.lock:
                self.connections.add(connection)
                self.sessions.add(worker)
            worker.start()

    def _session(self, connection, peer):
        transport = None
        interface = ForwardingInterface(self, peer)
        stopping = threading.Event()
        streams, workers = set(), set()
        streams_lock = threading.Lock()
        try:
            transport = paramiko.Transport(connection)
            transport.banner_timeout = transport.handshake_timeout = transport.auth_timeout = 10
            transport.set_log_channel("sservcli.ssh.server")
            transport.add_server_key(self.host_key)
            with self.lock:
                self.transports.add(transport)
            transport.start_server(server=interface)
            deadline = time.monotonic() + 10
            while transport.is_active() and not self.stopping.is_set():
                if not transport.is_authenticated() and time.monotonic() > deadline:
                    break
                channel = transport.accept(timeout=0.2)
                if channel is None:
                    continue
                with interface.lock:
                    destination = interface.destinations.pop(channel.get_id(), None)
                if destination is None:
                    channel.close()
                    continue

                def forward(channel=channel, destination=destination):
                    upstream = None
                    try:
                        upstream = socket.create_connection(destination, timeout=5)
                        upstream.settimeout(None)
                        with streams_lock:
                            streams.update((channel, upstream))
                        relay(channel, upstream, stopping)
                    except (OSError, EOFError):
                        pass
                    finally:
                        close_stream(channel)
                        if upstream:
                            close_stream(upstream)
                        with streams_lock:
                            streams.discard(channel)
                            streams.discard(upstream)
                            workers.discard(threading.current_thread())
                        interface.slots.release()
                        self.channel_slots.release()

                worker = threading.Thread(target=forward, daemon=True)
                with streams_lock:
                    workers.add(worker)
                worker.start()
        except (OSError, EOFError, paramiko.SSHException):
            # Never echo authentication data or untrusted SSH protocol text.
            pass
        finally:
            stopping.set()
            if transport:
                transport.close()
            close_stream(connection)
            with streams_lock:
                active_streams, active_workers = list(streams), list(workers)
            for stream in active_streams:
                close_stream(stream)
            for worker in active_workers:
                worker.join(timeout=6)
            with interface.lock:
                for _ in interface.destinations:
                    interface.slots.release()
                    self.channel_slots.release()
                interface.destinations.clear()
            with self.lock:
                self.connections.discard(connection)
                self.transports.discard(transport)
                self.sessions.discard(threading.current_thread())
            self.connection_slots.release()

    def close(self):
        self.stopping.set()
        if self.listener:
            self.listener.close()
        if self.thread:
            self.thread.join(timeout=2)
        with self.lock:
            transports, connections, workers = list(self.transports), list(self.connections), list(self.sessions)
        for transport in transports:
            transport.close()
        for connection in connections:
            close_stream(connection)
        for worker in workers:
            worker.join(timeout=8)
        if self.state_lock:
            self.state_lock.__exit__(None, None, None)
            self.state_lock = None
