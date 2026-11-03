"""Per-user desktop lock and authenticated local 'show window' notification."""
import json
import os
from pathlib import Path
import secrets
import socket
import threading


def state_directory():
    if os.name == "nt":
        directory = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData/Local"))) / "sservcli"
    else:
        directory = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / "sservcli"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    return directory


class Instance:
    def __init__(self, directory, actions):
        self.directory, self.actions = Path(directory), actions
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.file = None
        self.server = None
        self.thread = None
        self.stopping = threading.Event()

    def acquire(self):
        self.file = (self.directory / "desktop.lock").open("a+b")
        try:
            if os.name == "nt":
                import msvcrt
                self.file.seek(0)
                if not self.file.read(1):
                    self.file.write(b"0")
                    self.file.flush()
                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.file.close()
            self.file = None
            self.notify()
            return False
        try:
            self.server = socket.socket()
            self.server.bind(("127.0.0.1", 0))
            self.server.listen(2)
            self.server.settimeout(0.3)
            self.token = secrets.token_hex(32)
            path = self.directory / "desktop-ipc.json"
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump({"port": self.server.getsockname()[1], "token": self.token}, stream)
            self.thread = threading.Thread(target=self._listen, daemon=True)
            self.thread.start()
            return True
        except BaseException:
            self.close()
            raise

    def notify(self):
        # Another process may still be creating its IPC metadata.
        for _ in range(15):
            try:
                data = json.loads((self.directory / "desktop-ipc.json").read_text(encoding="utf-8"))
                with socket.create_connection(("127.0.0.1", int(data["port"])), timeout=0.3) as connection:
                    connection.sendall((data["token"] + "\n").encode("ascii"))
                return
            except (OSError, ValueError, KeyError):
                self.stopping.wait(0.1)
        raise OSError("sservcli is already running but its window could not be reached")

    def _listen(self):
        while not self.stopping.is_set():
            try:
                connection, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with connection:
                connection.settimeout(0.5)
                try:
                    data = bytearray()
                    while len(data) < 128 and not data.endswith(b"\n"):
                        chunk = connection.recv(128 - len(data))
                        if not chunk:
                            break
                        data.extend(chunk)
                    if secrets.compare_digest(bytes(data), (self.token + "\n").encode("ascii")):
                        self.actions.put("show")
                except OSError:
                    pass

    def close(self):
        self.stopping.set()
        if self.server:
            self.server.close()
        if self.thread:
            self.thread.join(timeout=2)
        if self.file:
            (self.directory / "desktop-ipc.json").unlink(missing_ok=True)
            if os.name == "nt":
                import msvcrt
                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
            self.file.close()
            self.file = None
