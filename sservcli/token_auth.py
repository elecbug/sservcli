"""Server tokens, persistent host identity, and local secret storage."""
import base64
import contextlib
import hashlib
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


def host_identity(directory):
    import io
    import paramiko
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    directory = private_directory(directory)
    with FileLock(directory / "host-key.lock"):
        path = directory / "host_ed25519"
        if not os.path.lexists(path):
            key = ed25519.Ed25519PrivateKey.generate()
            data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())
            write_private(path, data.decode("ascii"))
        key = paramiko.Ed25519Key.from_private_key(io.StringIO(read_private(path)))
        public = f"{key.get_name()} {key.get_base64()}"
        write_private(directory / "host_ed25519.pub", public + "\n")
        return key, public


def public_key(text):
    import paramiko
    try:
        kind, encoded = text.split()[:2]
        return paramiko.PKey.from_type_string(kind, base64.b64decode(encoded, validate=True))
    except (ValueError, TypeError, IndexError, paramiko.SSHException) as error:
        raise ConfigError("Invalid pinned server public key") from error


def token_slot(config):
    ssh = config["ssh"]
    identity = " ".join(ssh.get("host_public_key", "").split()[:2])
    return hashlib.sha256(f"{identity}:{ssh.get('port', 8022)}".encode()).hexdigest()


def store_token(directory, config, token):
    import json
    directory = private_directory(directory)
    path = directory / "tokens.json"
    values = json.loads(read_private(path)) if path.exists() else {}
    if not isinstance(values, dict):
        raise ConfigError("Saved token store is invalid")
    slot = token_slot(config)
    if token is None:
        values.pop(slot, None)
    else:
        token = validate_token(token)
        if os.name == "nt":
            from .windows import protect_secret
            token = "dpapi:" + protect_secret(token)
        values[slot] = token
    write_private(path, json.dumps(values))


def remembered_token(directory, config):
    import json
    path = Path(directory) / "tokens.json"
    try:
        values = json.loads(read_private(path))
        if not isinstance(values, dict):
            return None
        value = values.get(token_slot(config))
        if not isinstance(value, str):
            return None
        if os.name == "nt" and value and value.startswith("dpapi:"):
            from .windows import unprotect_secret
            value = unprotect_secret(value[6:])
        return validate_token(value) if value else None
    except (OSError, ValueError, TypeError):
        return None
