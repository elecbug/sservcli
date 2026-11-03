"""Token-authenticated SSH transport shared by all local service listeners."""
import hmac
import logging
import socket
import threading
import time

import paramiko

from .relay import close_stream, relay
from .token_auth import public_key

logging.getLogger("sservcli.ssh").addHandler(logging.NullHandler())
logging.getLogger("sservcli.ssh").propagate = False


def supervise(tunnel, config, token):
    try:
        key = public_key(config["ssh"]["host_public_key"])
        with tunnel._lock:
            tunnel._state["host_key_fingerprint"] = key.fingerprint
        tunnel.events.put(("pinned host key", key.fingerprint))
        session = TokenConnection(tunnel, config, token, key)
        tunnel._cycles(config, None, None, connection=session.run)
    except Exception:
        # Keep secrets and remote exception payloads out of logs and UI.
        tunnel._update("failed", "Could not establish token-authenticated SSH connection")


class TokenConnection:
    def __init__(self, tunnel, config, token, host_key):
        self.tunnel, self.config, self.token, self.host_key = tunnel, config, token, host_key

    def run(self, config, known, host, control, attempt):
        transport, connection = None, None
        listeners, acceptors, workers, streams = [], [], set(), set()
        stopping, lock = threading.Event(), threading.Lock()
        slots = threading.BoundedSemaphore(128)
        connected = False
        heartbeat = None
        try:
            connection = socket.create_connection((host, config["ssh"].get("port", 8022)), timeout=10)
            if self.tunnel._stop.is_set():
                return False, "Disconnected", False
            transport = paramiko.Transport(connection)
            self.tunnel._cancel = transport.close
            if self.tunnel._stop.is_set():
                return False, "Disconnected", False
            transport.banner_timeout = transport.handshake_timeout = transport.auth_timeout = 10
            transport.set_log_channel("sservcli.ssh.client")
            transport.start_client(timeout=10)
            actual = transport.get_remote_server_key()
            if actual.get_name() != self.host_key.get_name() or not hmac.compare_digest(actual.asbytes(), self.host_key.asbytes()):
                return False, "Server host key mismatch; the shared token was not sent", True
            if self.tunnel._stop.is_set():
                return False, "Disconnected", False
            transport.auth_password("sservcli", self.token, fallback=False)

            def forward(client, service):
                channel = None
                try:
                    channel = transport.open_channel("direct-tcpip", ("127.0.0.1", service["remote_port"]), client.getpeername(), timeout=10)
                    with lock:
                        streams.add(channel)
                    relay(client, channel, stopping)
                except (OSError, EOFError, paramiko.SSHException):
                    pass
                finally:
                    close_stream(client)
                    if channel:
                        close_stream(channel)
                    with lock:
                        streams.discard(client)
                        streams.discard(channel)
                        workers.discard(threading.current_thread())
                    slots.release()

            def accept(listener, service):
                while not stopping.is_set():
                    try:
                        client, _ = listener.accept()
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    if not slots.acquire(blocking=False):
                        client.close()
                        continue
                    worker = threading.Thread(target=forward, args=(client, service), daemon=True)
                    with lock:
                        streams.add(client)
                        workers.add(worker)
                    worker.start()

            for service in config["services"]:
                if not service.get("enabled", True):
                    continue
                listener = socket.socket()
                listeners.append(listener)
                if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                else:
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", service["local_port"]))
                listener.listen(64)
                listener.settimeout(0.3)
            for listener, service in zip(listeners, [s for s in config["services"] if s.get("enabled", True)]):
                worker = threading.Thread(target=accept, args=(listener, service), daemon=True)
                worker.start()
                acceptors.append(worker)
            connected = True
            self.tunnel._update("connected", f"Connected to {host}; local listeners ready (service health is not checked)", attempt, host)
            last_reply = [time.monotonic()]

            def keepalive():
                while not stopping.wait(20):
                    if transport.global_request("keepalive@sservcli", wait=True) is None:
                        return
                    last_reply[0] = time.monotonic()

            heartbeat = threading.Thread(target=keepalive, daemon=True)
            heartbeat.start()
            while not self.tunnel._stop.wait(0.1):
                if not transport.is_active():
                    return True, f"{host}: SSH connection closed", False
                if time.monotonic() - last_reply[0] > 65:
                    return True, f"{host}: SSH keepalive timed out", False
            return True, "Disconnected", False
        except paramiko.AuthenticationException:
            return False, "Shared token rejected. Check its case and the current server token; wait 60 seconds after repeated failed attempts.", True
        except (OSError, EOFError, paramiko.SSHException):
            return connected, f"{host}: SSH connection unavailable", False
        finally:
            stopping.set()
            for listener in listeners:
                listener.close()
            if transport:
                transport.close()
            if connection:
                close_stream(connection)
            for acceptor in acceptors:
                acceptor.join(timeout=2)
            with lock:
                active_streams, active_workers = list(streams), list(workers)
            for stream in active_streams:
                close_stream(stream)
            for worker in active_workers:
                worker.join(timeout=3)
            if heartbeat:
                heartbeat.join(timeout=2)
            self.tunnel._cancel = None
