"""Eight-character tokens and local secret storage; SSH uses system OpenSSH."""
import contextlib
import os
from pathlib import Path
import secrets
import stat
import string
import tempfile

from .config import ConfigError, validate_token

TOKEN_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + string.digits


def generate_token(previous=None):
    while True:
        token = "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(8))
        if token != previous:
            return token


def private_directory(path):
    path = Path(path).absolute()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise ConfigError("Server state must be a real directory, not a symbolic link")
    if os.name != "nt" and (info.st_uid != os.geteuid() or info.st_mode & 0o077):
        raise ConfigError("Server state directory must belong to this user and have mode 0700")
    return path


def read_private(path):
    if Path(path).is_symlink():
        raise ConfigError("Private state files cannot be symbolic links")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
            raise ConfigError("Invalid private state file")
        if os.name != "nt" and (info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise ConfigError("Private state files must belong to this user and have mode 0600")
        return stream.read()


def write_private(path, text):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix=".sservcli-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


class FileLock:
    def __init__(self, path):
        self.path = Path(path)
        self.file = None

    def __enter__(self):
        if self.path.is_symlink():
            raise ConfigError("State lock cannot be a symbolic link")
        descriptor = os.open(self.path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        self.file = os.fdopen(descriptor, "r+b")
        try:
            if os.name == "nt":
                import msvcrt
                if not self.file.read(1):
                    self.file.write(b"0")
                    self.file.flush()
                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            self.file.close()
            self.file = None
            raise ConfigError("Server state is already in use by another process") from error
        return self

    def __exit__(self, *_):
        if self.file:
            self.file.close()
            self.file = None
