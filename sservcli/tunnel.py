"""One managed OpenSSH process, ordered failover, and bounded reconnection."""
import base64
from collections import deque
import copy
import hashlib
import os
from pathlib import Path
import queue
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import webbrowser

from .config import ConfigError, launch_arguments, service_url, validate_profile, validate_token


def openssh_program(name="ssh"):
    if os.name == "nt":
        system = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        for folder in ("Sysnative", "System32"):
            candidate = system / folder / "OpenSSH" / (name + ".exe")
            if candidate.is_file():
                return str(candidate)
    found = shutil.which(name)
    if not found:
        raise ConfigError(f"Install OpenSSH Client; {name} was not found")
    return found


def process_options():
    return {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}


def ssh_path(value):
    value = str(value)
    if os.name == "nt":
        if value.startswith("\\\\?\\UNC\\"):
            value = "\\\\" + value[8:]
        elif value.startswith("\\\\?\\"):
            value = value[4:]
        value = value.replace("\\", "/")
    if any(ord(char) < 32 or char in '%"' for char in value):
        raise ConfigError("SSH paths cannot contain controls, quotes, or % tokens")
    return value


def prepare_host_key(ssh, directory):
    """Pin the same authenticated host key for every configured server address."""
    if not ssh.get("host_public_key"):
        return ssh["known_hosts_file"], None
    key = " ".join(ssh["host_public_key"].split()[:2])
    public = Path(directory) / "server.pub"
    public.write_text(key + "\n", encoding="ascii")
    result = subprocess.run([openssh_program("ssh-keygen"), "-lf", str(public)],
                            capture_output=True, text=True, timeout=10, **process_options())
    if result.returncode:
        raise ConfigError("Invalid server host public key: " + result.stderr.strip())
    blob = base64.b64decode(key.split()[1], validate=True)
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    port = ssh.get("port", 22)
    hosts = [ssh["host"], *ssh.get("fallback_hosts", [])]
    known = Path(directory) / "known_hosts"
    known.write_text("".join(f"{host if port == 22 else f'[{host}]:{port}'} {key}\n" for host in hosts), encoding="ascii")
    return str(known), fingerprint


def ssh_arguments(config, known_hosts, host=None, control=None):
    ssh = config["ssh"]
    args = ["-F", "none", "-N", "-T", "-n"]
    options = ["BatchMode=yes", "StrictHostKeyChecking=yes", "GlobalKnownHostsFile=none",
               "UpdateHostKeys=no", "ExitOnForwardFailure=yes", "ServerAliveInterval=20",
               "ServerAliveCountMax=3", "ConnectTimeout=10", "ConnectionAttempts=1",
               "PreferredAuthentications=publickey", "PasswordAuthentication=no",
               "KbdInteractiveAuthentication=no", "ForwardAgent=no", "ForwardX11=no",
               "GatewayPorts=no", "LogLevel=VERBOSE", f'UserKnownHostsFile="{ssh_path(known_hosts)}"']
    if os.name != "nt":
        options.append("ControlPersist=no")
        if control:
            options += ["ControlMaster=yes", f'ControlPath="{ssh_path(control)}"']
    if ssh.get("identity_file"):
        options.append("IdentitiesOnly=yes")
        args += ["-i", ssh_path(ssh["identity_file"])]
    for option in options:
        args += ["-o", option]
    args += ["-p", str(ssh.get("port", 22)), "-l", ssh["user"]]
    for service in config["services"]:
        if service.get("enabled", True):
            args += ["-L", f"127.0.0.1:{service['local_port']}:127.0.0.1:{service['remote_port']}"]
    return [*args, host or ssh["host"]]


def check_ports(config):
    sockets = []
    try:
        for service in config["services"]:
            if service.get("enabled", True):
                listener = socket.socket()
                sockets.append(listener)
                if os.name == "nt":
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                else:
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    listener.bind(("127.0.0.1", service["local_port"]))
                except OSError as error:
                    raise ConfigError(f"{service['id']}: local port {service['local_port']} is unavailable: {error}") from error
        if not sockets:
            raise ConfigError("Enable at least one service before connecting")
    finally:
        for listener in sockets:
            listener.close()


class Tunnel:
    def __init__(self):
        self._lock = threading.Lock()
        self._state = {"status": "disconnected", "message": "No SSH connection", "attempt": 0,
                       "active_host": None, "host_key_fingerprint": None}
        self._logs = deque(maxlen=200)
        self.events = queue.Queue()
        self._stop = threading.Event()
        self._worker = None
        self._cancel = None

    def snapshot(self):
        with self._lock:
            return {**self._state, "logs": list(self._logs)}

    def _update(self, status, message, attempt=0, host=None):
        with self._lock:
            self._state.update(status=status, message=message, attempt=attempt, active_host=host)
            self._logs.append(message)
        self.events.put((status, message))

    def connect(self, config, token=None):
        validate_profile(config)
        if self._worker and self._worker.is_alive():
            raise ConfigError("Disconnect the current connection first")
        self.disconnect()
        token_mode = config["version"] == 2
        if token_mode:
            validate_token(token)
            if not config["ssh"].get("host_public_key"):
                raise ConfigError("Import the server's client bundle or supply its public host key before connecting")
            try:
                from .token_tunnel import supervise
                from .token_auth import public_key
                public_key(config["ssh"]["host_public_key"])
            except ImportError as error:
                raise ConfigError("Install Python dependencies with make setup or Build.cmd") from error
        else:
            openssh_program()
            for field in ("known_hosts_file", "identity_file"):
                if config["ssh"].get(field) and not Path(config["ssh"][field]).is_file():
                    raise ConfigError(f"{field} does not exist: {config['ssh'][field]}")
        check_ports(config)
        self._stop.clear()
        with self._lock:
            self._logs.clear()
            self._state["host_key_fingerprint"] = None
        self._update("connecting", "Preparing SSH connection")
        target = supervise if token_mode else self._supervise
        arguments = (self, copy.deepcopy(config), token) if token_mode else (copy.deepcopy(config),)
        self._worker = threading.Thread(target=target, args=arguments, daemon=True)
        self._worker.start()

    def disconnect(self):
        self._stop.set()
        cancel = self._cancel
        if cancel:
            cancel()
        if self._worker:
            self._worker.join(timeout=15)
            if self._worker.is_alive():
                raise ConfigError("SSH is still stopping; wait before reconnecting")
            self._worker = None
        if self.snapshot()["status"] != "disconnected":
            self._update("disconnected", "SSH connection closed; local listeners released")

    def _supervise(self, config):
        try:
            # Unix socket paths must remain short even when the user's temp path is long.
            with tempfile.TemporaryDirectory(prefix=f"sservcli-{os.getpid()}-", dir=None if os.name == "nt" else "/tmp") as directory:
                known, fingerprint = prepare_host_key(config["ssh"], directory)
                with self._lock:
                    self._state["host_key_fingerprint"] = fingerprint
                if fingerprint:
                    self.events.put(("pinned host key", fingerprint))
                control = str(Path(directory) / "ctl") if os.name != "nt" else None
                self._cycles(config, known, control)
        except Exception as error:
            self._update("failed", str(error))

    def _cycles(self, config, known, control, connection=None):
        hosts = [config["ssh"]["host"], *config["ssh"].get("fallback_hosts", [])]
        reconnect = config.get("reconnect", {})
        maximum = reconnect.get("max_attempts", 5)
        retries, first = 0, 0
        while not self._stop.is_set():
            was_connected, message = False, "SSH connection failed"
            for offset in range(len(hosts)):
                if self._stop.is_set():
                    break
                index = (first + offset) % len(hosts)
                host = hosts[index]
                self._update("connecting", f"Connecting to {host}:{config['ssh'].get('port', 8022 if config['version'] == 2 else 22)} (address {offset + 1}/{len(hosts)})", retries)
                if control:
                    Path(control).unlink(missing_ok=True)
                was_connected, message, fatal = (connection or self._connection)(config, known, host, control, retries)
                if fatal:
                    self._update("failed", message, retries)
                    return
                if was_connected:
                    first = (index + 1) % len(hosts)
                    break
            if self._stop.is_set():
                break
            if not reconnect.get("enabled", True) or (not was_connected and retries == 0) or retries >= maximum:
                self._update("failed", message, retries)
                return
            retries += 1
            delay = min(reconnect.get("initial_delay_secs", 2) * 2 ** (retries - 1), reconnect.get("max_delay_secs", 30))
            self._update("reconnecting", f"{message}; retry {retries}/{maximum} in {delay}s", retries)
            if self._stop.wait(delay):
                break
        self._update("disconnected", "SSH connection closed; local listeners released", retries)

    def _connection(self, config, known, host, control, attempt):
        child = None
        reader = None
        job = None
        connected = False
        lines = deque(maxlen=50)
        try:
            child = subprocess.Popen([openssh_program(), *ssh_arguments(config, known, host, control)],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                     start_new_session=os.name != "nt", **process_options())
            if os.name == "nt":
                from .windows import ChildJob
                job = ChildJob(child)

            def drain():
                while data := child.stderr.readline(4096):
                    line = "".join(c for c in data.decode("utf-8", "replace").rstrip() if c.isprintable())
                    lines.append(line)
                    with self._lock:
                        self._logs.append(line)

            reader = threading.Thread(target=drain, daemon=True)
            reader.start()
            deadline = time.monotonic() + 20
            while not self._stop.wait(0.1):
                if child.poll() is not None:
                    reader.join(timeout=2)
                    fatal = any(token in line for line in lines for token in ("HOST IDENTIFICATION HAS CHANGED", "Host key verification failed", "Permission denied"))
                    return connected, f"{host}: SSH exited with {child.returncode}; see connection log", fatal
                if not connected and self._ready(child, host, control, config):
                    connected = True
                    self._update("connected", f"Connected to {host}; local listeners ready (service health is not checked)", attempt, host)
                if not connected and time.monotonic() > deadline:
                    return False, f"{host}: SSH startup timed out; see connection log", False
            return connected, "Disconnected", False
        finally:
            if child:
                if child.poll() is None:
                    if os.name == "nt":
                        child.terminate()
                    else:
                        try:
                            os.killpg(child.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=3)
                if job:
                    job.close()
                if reader:
                    reader.join(timeout=3)
                child.stderr.close()

    @staticmethod
    def _ready(child, host, control, config):
        if os.name == "nt":
            from .windows import listeners_owned_by
            return listeners_owned_by(child.pid, [s["local_port"] for s in config["services"] if s.get("enabled", True)])
        if not Path(control).exists():
            return False
        result = subprocess.run([openssh_program(), "-F", "none", "-S", control, "-O", "check", host],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        return result.returncode == 0


def launch_service(service):
    if not service.get("enabled", True):
        raise ConfigError("Enable and connect this service first")
    argv = launch_arguments(service)
    if argv:
        # Profiles are trusted local files: executables and arguments run without a shell.
        child = subprocess.Popen(argv, shell=False)
        threading.Thread(target=child.wait, daemon=True).start()
    elif service["kind"] in ("web", "api"):
        webbrowser.open(service_url(service))
    else:
        raise ConfigError("Configure this service's launch argument array or use its local endpoint")
