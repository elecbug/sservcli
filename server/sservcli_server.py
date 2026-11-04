#!/usr/bin/env python3
"""Provision an Ubuntu/OpenSSH forwarding account; no custom server daemon."""
import argparse
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import secrets
import signal
import string


class SetupError(Exception):
    pass


POLICY = {
    "AuthenticationMethods": "publickey",
    "PubkeyAuthentication": "yes",
    "PasswordAuthentication": "no",
    "KbdInteractiveAuthentication": "no",
    "MaxSessions": "0",
    "AllowTcpForwarding": "local",
    "AllowStreamLocalForwarding": "no",
    "AllowAgentForwarding": "no",
    "X11Forwarding": "no",
    "PermitTTY": "no",
    "PermitTunnel": "no",
    "PermitUserRC": "no",
    "PermitListen": "none",
}


def run(argv, *, check=True):
    result = subprocess.run(argv, text=True, capture_output=True, check=False)
    if check and result.returncode:
        raise SetupError(f"{argv[0]} failed: {result.stderr.strip() or result.stdout.strip()}")
    return result


def username(value):
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", value) or value == "root":
        raise SetupError("Use a dedicated non-root username ([a-z_][a-z0-9_-]{0,31})")
    return value


def destinations(values):
    if not values or len(values) > 64:
        raise SetupError("Supply between 1 and 64 forwarding destinations")
    result = []
    for value in values:
        match = re.fullmatch(r"127\.0\.0\.1:([1-9][0-9]{0,4})", value)
        if not match or int(match[1]) > 65535:
            raise SetupError(f"Invalid destination: {value!r}; use 127.0.0.1:<1-65535>")
        if value not in result:
            result.append(value)
    return result


def policy_input(args):
    if args.config:
        if args.user is not None or args.permit_open is not None:
            raise SetupError("Use --config or --user/--permit-open, not both")
        config = json.loads(Path(args.config).read_text())
        if type(config.get("version")) is not int or config["version"] not in (1, 2):
            raise SetupError("Only configuration versions 1 and 2 are supported")
        user = config["ssh"].get("user", "svc_tunnel")
        # Include disabled services: enabled is a client preference, not authorization.
        values = []
        for service in config["services"]:
            if type(service["remote_port"]) is not int:
                raise SetupError("remote_port must be an integer")
            values.append(f'{service["remote_host"]}:{service["remote_port"]}')
    else:
        user = args.user or "svc_tunnel"
        values = args.permit_open
    return username(user), destinations(values)


def markers(user):
    return f"# BEGIN sservcli {user}", f"# END sservcli {user}"


def policy_options(user, permitted, mode="key"):
    options = {**POLICY, "PermitOpen": " ".join(permitted),
               "AuthorizedKeysFile": f"/home/{user}/.ssh/authorized_keys"}
    if mode == "token":
        options.update(AuthenticationMethods="password", PubkeyAuthentication="no", PasswordAuthentication="yes",
                       AuthorizedKeysFile="none", MaxAuthTries="3")
    return options


def policy(user, permitted, mode="key"):
    begin, end = markers(user)
    options = policy_options(user, permitted, mode)
    return (f"{begin}\nMatch User {user}\n" +
            "".join(f"    {key} {value}\n" for key, value in options.items()) +
            f"{end}\nMatch all\n")


def restricted_key(text, permitted):
    lines = text.splitlines()
    if len(lines) != 1 or not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [^\r\n]*)?", lines[0]):
        raise SetupError("Expected exactly one plain ssh-ed25519 public key, without authorized_keys options")
    # Validate the actual key blob, rather than its text prefix alone.
    with tempfile.NamedTemporaryFile(mode="w", prefix="sservcli-pubkey-") as key:
        key.write(text)
        key.flush()
        run(["ssh-keygen", "-lf", key.name])
    return f"{key_options(permitted)} {lines[0]}\n"


def key_options(permitted):
    return "restrict,port-forwarding" + "".join(f',permitopen="{item}"' for item in permitted)


def merge_key(existing, public_key, permitted):
    """Append a new key or extend our existing entry, preserving other entries."""
    wanted = restricted_key(public_key, permitted)
    identity = tuple(public_key.split()[:2])
    # Read only options/type/blob. Comments may contain unmatched quotes, and
    # option values may contain spaces, so splitting the entire line is unsafe.
    entry = re.compile(r'^(?:(?P<options>(?:[^\s"]|"(?:[^"\\]|\\.)*")+)\s+)?'
                       r'(?P<kind>ssh-ed25519)\s+(?P<blob>[A-Za-z0-9+/]+={0,2})(?:\s|$)')
    lines = existing.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.lstrip().startswith("#"):
            continue
        match = entry.match(line.lstrip())
        if not match or (match["kind"], match["blob"]) != identity:
            continue
        options = match["options"] or ""
        previous = re.findall(r'permitopen="(127\.0\.0\.1:[0-9]+)"', options)
        # Leave administrator-supplied options (from=, command=, etc.) intact.
        if not previous or options != key_options(previous):
            return existing, "unchanged"
        combined = destinations(list(dict.fromkeys([*previous, *permitted])))
        if combined == previous:
            return existing, "unchanged"
        lines[index] = line.replace(options, key_options(combined), 1)
        return "".join(lines), "updated"
    separator = "\n" if existing and not existing.endswith("\n") else ""
    return existing + separator + wanted, "added"


def managed_block(text, user):
    begin, end = markers(user)
    if text.splitlines().count(begin) != 1 or text.splitlines().count(end) != 1:
        raise SetupError("Expected exactly one complete managed policy block")
    pattern = re.compile(rf"^{re.escape(begin)}\n.*?^{re.escape(end)}\nMatch all\n", re.M | re.S)
    match = pattern.search(text)
    if not match:
        raise SetupError("Managed policy was edited; refusing to remove it")
    return match


def account(user):
    try:
        return pwd.getpwnam(user)
    except KeyError:
        return None


def safe_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise SetupError(f"{path} must be a root-owned regular file without group/world write access")
    return info


def safe_directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise SetupError(f"{path} must be a root-owned directory without group/world write access")
    return info


def ensure_state_dir(path):
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise SetupError(f"{path} must be a root-owned directory with mode 0700")


def atomic_write(path, text, *, mode=0o600, owner=(0, 0)):
    fd, temp = tempfile.mkstemp(prefix=".sservcli-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), *owner)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


class Provisioner:
    def __init__(self, args):
        self.config = Path(args.sshd_config)
        self.state_dir = Path("/var/lib/sservcli")
        self.home_base = Path("/home")
        self.service = args.ssh_service
        if not re.fullmatch(r"[a-zA-Z0-9_.@-]+", self.service) or self.service.startswith("-"):
            raise SetupError("Invalid SSH systemd service name")
        self.sshd = shutil.which("sshd") or "/usr/sbin/sshd"
        self.pid_file = Path(args.sshd_pid_file) if getattr(args, "sshd_pid_file", None) else None
        self.context = f"host=localhost,addr={args.client_address}"
        if not re.fullmatch(r"[0-9a-fA-F:.]+", args.client_address):
            raise SetupError("--client-address must be an IP address")

    def syntax(self):
        run([self.sshd, "-t", "-f", str(self.config)])

    def audit(self, user, permitted, mode="key"):
        self.syntax()
        result = run([self.sshd, "-T", "-f", str(self.config), "-C", f"user={user},{self.context}"])
        effective = dict(line.split(" ", 1) for line in result.stdout.splitlines() if " " in line)
        expected = policy_options(user, permitted, mode)
        for key, value in expected.items():
            actual = effective.get(key.lower())
            if actual != value:
                raise SetupError(f"Effective {key} is {actual!r}, expected {value!r}; inspect earlier Match/Include rules")
        if effective.get("disableforwarding") == "yes":
            raise SetupError("DisableForwarding prevents the configured tunnels")
        return result.stdout

    def daemon_pid(self):
        safe_file(self.pid_file)
        value = self.pid_file.read_text().strip()
        if not re.fullmatch(r"[1-9][0-9]{0,9}", value) or int(value) <= 1:
            raise SetupError("Invalid OpenSSH daemon PID file")
        pid = int(value)
        try:
            executable = Path(f"/proc/{pid}/exe").resolve(strict=True)
        except OSError as error:
            raise SetupError("OpenSSH daemon is not running") from error
        if executable != Path(self.sshd).resolve():
            raise SetupError("PID file does not refer to the OpenSSH daemon")
        return pid

    def ensure_ssh(self):
        if self.pid_file:
            self.syntax()
            self.daemon_pid()
        else:
            run(["ssh-keygen", "-A"])
            run(["systemctl", "enable", "--now", self.service])

    def reload(self):
        if self.pid_file:
            os.kill(self.daemon_pid(), signal.SIGHUP)
        else:
            run(["systemctl", "reload", self.service])

    def restore(self, original, info):
        atomic_write(self.config, original, mode=stat.S_IMODE(info.st_mode), owner=(info.st_uid, info.st_gid))
        # A failed reload may have partially affected the daemon. Reload the restored policy.
        try:
            self.reload()
        except (SetupError, OSError) as error:
            print(f"Rollback restored the file, but SSH reload failed: {error}", file=sys.stderr)

    def state_path(self, user):
        return self.state_dir / f"{user}.json"

    def audit_destinations(self, user, requested):
        """Audit retained destinations too, without accepting unrecorded edits."""
        state_path = self.state_path(user)
        if not os.path.lexists(state_path):
            return requested
        safe_directory(self.state_dir)
        safe_file(state_path)
        record = json.loads(state_path.read_text())
        safe_file(self.config)
        block = managed_block(self.config.read_text(), user)[0]
        if (record["user"] != user or record["sshd_config"] != str(self.config.resolve())
                or hashlib.sha256(block.encode()).hexdigest() != record["block_sha256"]):
            raise SetupError("Managed account/configuration metadata differs; cannot audit retained destinations")
        allowed = re.search(r"^    PermitOpen (.+)$", block, re.M)
        if not allowed:
            raise SetupError("Managed policy has no forwarding allowlist")
        permitted = destinations(allowed[1].split())
        if not set(requested).issubset(permitted):
            raise SetupError("The account does not permit all requested destinations; run bundle to register them")
        return permitted

    def ensure(self, user, permitted, key_path):
        """Idempotent bundle setup. Only install() creates an owned account."""
        if not account(user):
            self.install(user, permitted, key_path)
            return {"user": user, "created": True, "account": "created", "key": "added"}
        if not os.path.lexists(self.state_path(user)):
            # Do not take ownership of an unrelated account or change its login
            # policy. Existing authentication remains the administrator's setup.
            return {"user": user, "created": False, "account": "external", "key": "unchanged",
                    "message": "Existing account is not managed by sservcli; skipped account/key/policy changes. Its existing SSH setup must already authorize the client key and allow the configured forwarding destinations."}
        key_status = self.bind_key(user, permitted, key_path)
        return {"user": user, "created": False, "account": "reused", "key": key_status}

    def resolve_token_user(self, preferred):
        """Reuse managed accounts; leave unrelated accounts and homes untouched."""
        ensure_state_dir(self.state_dir)
        for index in range(100):
            user = preferred if index == 0 else preferred[:22] + f"_token{index}"
            entry = account(user)
            recorded = os.path.lexists(self.state_path(user))
            if entry and recorded:
                self.managed_identity(user)
                return user
            if not entry and not recorded and not os.path.lexists(self.home_base / user):
                return user
        raise SetupError("Could not select an unused dedicated SSH token account")

    def managed_identity(self, user):
        safe_directory(self.state_dir)
        path = self.state_path(user)
        safe_file(path)
        record = json.loads(path.read_text())
        safe_file(self.config)
        block = managed_block(self.config.read_text(), user)[0]
        entry = account(user)
        if (record["user"] != user or record["sshd_config"] != str(self.config.resolve())
                or hashlib.sha256(block.encode()).hexdigest() != record["block_sha256"]):
            raise SetupError("Managed account/configuration metadata differs")
        if (not entry or entry.pw_uid == 0 or entry.pw_uid != record["uid"] or entry.pw_dir != record["home"]
                or record["home"] != str(self.home_base / user) or entry.pw_shell != "/usr/sbin/nologin"):
            raise SetupError("Managed account properties changed")
        for directory in (self.home_base, self.home_base / user):
            safe_directory(directory)
        return record, entry, block

    def ensure_token(self, user, permitted, *, activate=True):
        info = safe_file(self.config)
        original = self.config.read_text()
        home = self.home_base / user
        created = False
        state_path = self.state_path(user)
        previous_state = None
        if account(user):
            record, entry, old_block = self.managed_identity(user)
            previous_state = state_path.read_text()
            allowed = re.search(r"^    PermitOpen (.+)$", old_block, re.M)
            if not allowed:
                raise SetupError("Managed policy has no forwarding allowlist")
            permitted = destinations(list(dict.fromkeys([*allowed[1].split(), *permitted])))
            match = managed_block(original, user)
        else:
            if os.path.lexists(home) or os.path.lexists(state_path) or markers(user)[0] in original:
                raise SetupError("Cannot take over an unmanaged home or policy")
            record, match = {}, None
            ensure_state_dir(self.state_dir)
        block = policy(user, permitted, "token")
        updated = original[:match.start()] + block + original[match.end():] if match else original.rstrip("\n") + "\n\n" + block
        changed = updated != original
        try:
            self.syntax()
            if not account(user):
                run(["useradd", "--no-create-home", "--home-dir", str(home), "--user-group", "--shell", "/usr/sbin/nologin",
                     "--password", "*", "--comment", "sservcli OpenSSH token account", user])
                created = True
                home.mkdir(mode=0o755)
                os.chown(home, 0, 0)
                os.chmod(home, 0o755)
            if changed:
                atomic_write(self.config, updated, mode=stat.S_IMODE(info.st_mode), owner=(info.st_uid, info.st_gid))
            self.audit(user, permitted, "token")
            was_token = record.get("auth_mode") == "token"
            record.update(user=user, uid=account(user).pw_uid, home=str(home), sshd_config=str(self.config.resolve()),
                          block_sha256=hashlib.sha256(block.encode()).hexdigest(), auth_mode="token")
            atomic_write(state_path, json.dumps(record, indent=2) + "\n")
            if changed and activate:
                self.reload()
            if not was_token:
                self.lock_token(user, record["uid"])
        except BaseException:
            if changed:
                self.restore(original, info)
            if created:
                run(["userdel", "--remove", user], check=False)
                if home.is_dir() and not home.is_symlink() and not account(user):
                    shutil.rmtree(home)
                state_path.unlink(missing_ok=True)
            elif previous_state is not None:
                atomic_write(state_path, previous_state)
            raise
        return {"user": user, "uid": record["uid"], "created": created, "permitted": permitted}

    def set_token(self, user, token):
        if not re.fullmatch(r"[A-Za-z0-9]{8}", token):
            raise SetupError("Expected an eight-character base62 token")
        record, _, _ = self.managed_identity(user)
        if record.get("auth_mode") != "token":
            raise SetupError("This managed account is not configured for token passwords")
        result = subprocess.run(["chpasswd"], input=f"{user}:{token}\n", text=True, capture_output=True)
        if result.returncode:
            raise SetupError("Could not set the dedicated SSH password; check the system's password policy")

    def lock_token(self, user, uid):
        record, entry, _ = self.managed_identity(user)
        if entry.pw_uid != uid or record.get("auth_mode") != "token":
            raise SetupError("Refusing to lock an account whose identity or authentication mode changed")
        run(["usermod", "--lock", user])
        result = run(["pkill", "-KILL", "-u", str(uid)], check=False)
        if result.returncode not in (0, 1):
            raise SetupError("Could not close existing SSH forwarding sessions for the token account")

    def bind_key(self, user, permitted, key_path):
        """Reuse a managed identity; never delete it when an update fails."""
        safe_directory(self.state_dir)
        state_path = self.state_path(user)
        state_info = safe_file(state_path)
        state_original = state_path.read_text()
        record = json.loads(state_original)
        if record.get("auth_mode") == "token":
            raise SetupError("This account uses SSH token passwords; use token mode rather than registering a login key")
        info = safe_file(self.config)
        original = self.config.read_text()
        match = managed_block(original, user)
        block = match[0]
        if (record["user"] != user or record["sshd_config"] != str(self.config.resolve())
                or hashlib.sha256(block.encode()).hexdigest() != record["block_sha256"]):
            raise SetupError("Managed account/configuration metadata differs; refusing key updates")
        entry = account(user)
        home = self.home_base / user
        if (not entry or entry.pw_uid == 0 or entry.pw_uid != record["uid"]
                or entry.pw_dir != record["home"] or record["home"] != str(home)
                or entry.pw_shell != "/usr/sbin/nologin"):
            raise SetupError("Account properties changed; refusing key updates")
        for path in (self.home_base, home, home / ".ssh"):
            safe_directory(path)
        key_file = home / ".ssh/authorized_keys"
        key_info = safe_file(key_file)
        key_original = key_file.read_text()
        key, key_status = merge_key(key_original, Path(key_path).read_text(), permitted)
        allowed = re.search(r"^    PermitOpen (.+)$", block, re.M)
        if not allowed:
            raise SetupError("Managed policy has no forwarding allowlist")
        combined = destinations(list(dict.fromkeys([*allowed[1].split(), *permitted])))
        updated_block = policy(user, combined)
        # Existing destinations remain available to previously registered keys.
        # Each added key is still limited by its own permitopen options.
        updated = original[:match.start()] + updated_block + original[match.end():]
        changed = updated != original
        state_changed = False
        key_changed = False
        try:
            if changed:
                atomic_write(self.config, updated, mode=stat.S_IMODE(info.st_mode), owner=(info.st_uid, info.st_gid))
            self.audit(user, combined)
            if changed:
                record["block_sha256"] = hashlib.sha256(updated_block.encode()).hexdigest()
                state_changed = True
                atomic_write(state_path, json.dumps(record, indent=2) + "\n",
                             mode=stat.S_IMODE(state_info.st_mode), owner=(state_info.st_uid, state_info.st_gid))
                self.reload()
            if key_status != "unchanged":
                # Grant the additional credential only after policy activation.
                key_changed = True
                atomic_write(key_file, key, mode=stat.S_IMODE(key_info.st_mode), owner=(key_info.st_uid, key_info.st_gid))
        except BaseException as error:
            failures = []
            for needed, path, text, previous_info in (
                (key_changed, key_file, key_original, key_info),
                (state_changed, state_path, state_original, state_info),
            ):
                if needed:
                    try:
                        atomic_write(path, text, mode=stat.S_IMODE(previous_info.st_mode), owner=(previous_info.st_uid, previous_info.st_gid))
                    except (OSError, SetupError) as restore_error:
                        failures.append(f"{path}: {restore_error}")
            if changed:
                try:
                    self.restore(original, info)
                except (OSError, SetupError) as restore_error:
                    failures.append(f"{self.config}: {restore_error}")
            if failures:
                raise SetupError(f"Key update failed ({error}); rollback needs administrator recovery: {'; '.join(failures)}") from error
            raise
        return key_status

    def install(self, user, permitted, key_path):
        info = safe_file(self.config)
        original = self.config.read_text()
        home = self.home_base / user
        if account(user) or os.path.lexists(home):
            raise SetupError("Account or home already exists; refusing to modify an existing user")
        if f"# BEGIN forwarding-only {user}" in original or markers(user)[0] in original:
            raise SetupError("A policy for this account already exists")
        if not Path("/usr/sbin/nologin").is_file():
            raise SetupError("This installer requires Ubuntu's /usr/sbin/nologin")
        key = restricted_key(Path(key_path).read_text(), permitted)
        ensure_state_dir(self.state_dir)
        state_path = self.state_path(user)
        if os.path.lexists(state_path):
            raise SetupError("Managed account metadata already exists")
        self.syntax()
        block = policy(user, permitted)
        created = False
        changed = False
        try:
            run(["useradd", "--no-create-home", "--home-dir", str(home), "--user-group",
                 "--shell", "/usr/sbin/nologin", "--password", "*", "--comment", "sservcli forwarding account", user])
            created = True
            # Only root can change the access policy or authorized key.
            # Do not copy a system skeleton that might contain authorized keys.
            home.mkdir(mode=0o755)
            os.chown(home, 0, 0)
            os.chmod(home, 0o755)
            ssh_dir = home / ".ssh"
            # sshd reads authorized_keys as the target user. Public key material
            # must be readable, while directory and file writes remain root-only.
            ssh_dir.mkdir(mode=0o755)
            os.chmod(ssh_dir, 0o755)
            atomic_write(self.config, original.rstrip("\n") + "\n\n" + block,
                         mode=stat.S_IMODE(info.st_mode), owner=(info.st_uid, info.st_gid))
            changed = True
            self.audit(user, permitted)
            record = {"user": user, "uid": account(user).pw_uid, "home": str(home),
                      "sshd_config": str(self.config.resolve()), "block_sha256": hashlib.sha256(block.encode()).hexdigest()}
            atomic_write(state_path, json.dumps(record, indent=2) + "\n")
            self.reload()
            # Publish the credential only after sshd is enforcing the policy.
            atomic_write(ssh_dir / "authorized_keys", key, mode=0o644)
        except BaseException:
            if changed:
                self.restore(original, info)
            if created:
                cleanup = run(["userdel", "--remove", user], check=False)
                if account(user):
                    print(f"Rollback could not remove account {user}: {cleanup.stderr}", file=sys.stderr)
                elif home.is_dir() and not home.is_symlink():
                    # userdel may refuse a deliberately root-owned home.
                    shutil.rmtree(home)
            state_path.unlink(missing_ok=True)
            raise
        print(f"Created {user}; permitted destinations: {' '.join(permitted)}")

    def remove(self, user):
        state_path = self.state_path(user)
        safe_file(state_path)
        record = json.loads(state_path.read_text())
        info = safe_file(self.config)
        original = self.config.read_text()
        match = managed_block(original, user)
        # A failed previous cleanup may have retained our added denial. Accept
        # that exact restriction while still refusing other policy edits.
        canonical = match[0].replace(f"    DenyUsers {user}\n", "", 1)
        if record["user"] != user or record["sshd_config"] != str(self.config.resolve()) or hashlib.sha256(canonical.encode()).hexdigest() != record["block_sha256"]:
            raise SetupError("Managed account/configuration metadata differs; refusing deletion")
        entry = account(user)
        if entry and (entry.pw_uid != record["uid"] or entry.pw_dir != record["home"] or entry.pw_shell != "/usr/sbin/nologin"):
            raise SetupError("Account properties changed; refusing deletion")
        if Path(record["home"]).is_symlink():
            raise SetupError("Managed home is a symbolic link; refusing deletion")
        self.syntax()
        # First deny new authentication. Keep the restrictive policy until the
        # account has been removed; stop existing sessions before deleting it.
        denied_block = canonical.replace(f"Match User {user}\n", f"Match User {user}\n    DenyUsers {user}\n", 1)
        denied = original[:match.start()] + denied_block + original[match.end():]
        atomic_write(self.config, denied, mode=stat.S_IMODE(info.st_mode), owner=(info.st_uid, info.st_gid))
        removed = False
        try:
            self.syntax()
            self.reload()
            if entry:
                result = run(["pkill", "-KILL", "-u", str(entry.pw_uid)], check=False)
                if result.returncode not in (0, 1):
                    raise SetupError(f"Could not stop managed account processes: {result.stderr}")
                result = run(["userdel", "--remove", user], check=False)
                if account(user):
                    raise SetupError(f"Could not remove managed account: {result.stderr}")
                if result.returncode:
                    print(f"Account removed; userdel reported: {result.stderr.strip()}", file=sys.stderr)
            removed = True
            home = Path(record["home"])
            if home.exists():
                if home.is_symlink() or home.lstat().st_uid != 0:
                    raise SetupError("Account removed, but home ownership changed; manual cleanup required")
                shutil.rmtree(home)
        except BaseException:
            if removed:
                raise SetupError("Account removed, but home cleanup failed; denying block and metadata retained for recovery")
            self.restore(original, info)
            raise
        # Account is now gone. If cleanup fails, retain the denying policy so a
        # recreated username cannot inherit an accidentally permissive policy.
        final = original[:match.start()] + original[match.end():]
        try:
            atomic_write(self.config, final, mode=stat.S_IMODE(info.st_mode), owner=(info.st_uid, info.st_gid))
            self.syntax()
            self.reload()
        except BaseException:
            atomic_write(self.config, denied, mode=stat.S_IMODE(info.st_mode), owner=(info.st_uid, info.st_gid))
            with contextlib.suppress(SetupError, OSError):
                self.reload()
            raise SetupError("Account removed, but policy cleanup failed; denying block and metadata retained for recovery")
        state_path.unlink()
        print(f"Removed managed account and policy: {user}")


@contextlib.contextmanager
def management_lock():
    with open("/run/lock/sservcli.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def host_public_key(path, provisioner=None):
    path = Path(path)
    if not path.is_file() or path.stat().st_size > 16384:
        raise SetupError("Expected a small OpenSSH host public key file")
    text = path.read_text().strip()
    if len(text) > 16384 or not re.fullmatch(r"(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) [A-Za-z0-9+/=]+(?: [^\r\n]*)?", text):
        raise SetupError("Expected a plain OpenSSH server host PUBLIC key")
    run(["ssh-keygen", "-lf", str(path)])
    public = " ".join(text.split()[:2])
    if provisioner:
        effective = run([provisioner.sshd, "-T", "-f", str(provisioner.config)]).stdout
        configured = []
        for line in effective.splitlines():
            if line.startswith("hostkey "):
                candidate = Path(line.partition(" ")[2].strip('"') + ".pub")
                if candidate.is_file() and candidate.stat().st_size <= 16384:
                    configured.append(" ".join(candidate.read_text().split()[:2]))
        if public not in configured:
            raise SetupError("HOST_KEY_FILE does not match a HostKey used by the existing sshd")
    return public


def token_command(args, provisioner, preferred, permitted):
    account_lock = None
    ready = None
    reuse_token = None
    if getattr(args, "reuse_token_stdin", False):
        # This stdin is the private lifetime pipe from the approved host bridge.
        line = sys.stdin.readline(257)
        try:
            message = json.loads(line)
        except ValueError as error:
            raise SetupError("Invalid saved-token request") from error
        if (args.command != "token-serve" or len(line) > 256 or not line.endswith("\n")
                or not isinstance(message, dict) or set(message) != {"token"}
                or not isinstance(message["token"], str) or not re.fullmatch(r"[A-Za-z0-9]{8}", message["token"])):
            raise SetupError("Invalid saved-token request")
        reuse_token = message["token"]
    try:
        with management_lock():
            if args.ensure_ssh:
                provisioner.ensure_ssh()
            public = host_public_key(args.host_key, provisioner)
            user = provisioner.resolve_token_user(preferred)
            if args.command == "token-serve":
                account_lock = open(f"/run/lock/sservcli-token-{user}.lock", "a")
                try:
                    fcntl.flock(account_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as error:
                    raise SetupError("A token controller is already running for this SSH account") from error
            if reuse_token is not None:
                record, _, _ = provisioner.managed_identity(user)
                previous = record.get("last_token_sha256")
                if (record.get("auth_mode") != "token" or not isinstance(previous, str)
                        or not hmac.compare_digest(previous, hashlib.sha256(reuse_token.encode()).hexdigest())):
                    raise SetupError("Saved token does not match this managed SSH account; retry without NO_RESET_TOKEN to issue a new token")
            elif getattr(args, "no_reset_token", False) and account(user):
                record, _, _ = provisioner.managed_identity(user)
                if record.get("last_token_sha256"):
                    raise SetupError("A previous token exists but the saved token file is missing; restore /state/access.token or retry without NO_RESET_TOKEN")
            receipt = provisioner.ensure_token(user, permitted)
            if account_lock:
                ready = receipt
                record = json.loads(provisioner.state_path(user).read_text())
                alphabet = string.ascii_letters + string.digits
                if reuse_token is not None:
                    token = reuse_token
                    digest = hashlib.sha256(token.encode()).hexdigest()
                else:
                    while True:
                        token = "".join(secrets.choice(alphabet) for _ in range(8))
                        digest = hashlib.sha256(token.encode()).hexdigest()
                        if digest != record.get("last_token_sha256"):
                            break
                provisioner.set_token(user, token)
                # Password rotation does not terminate authenticated transports.
                result = run(["pkill", "-KILL", "-u", str(receipt["uid"])], check=False)
                if result.returncode not in (0, 1):
                    raise SetupError("Could not close previous token forwarding sessions")
                record["last_token_sha256"] = digest
                atomic_write(provisioner.state_path(user), json.dumps(record, indent=2) + "\n")
                receipt.update(token=token, token_reused=reuse_token is not None)
            if not account_lock:
                record = json.loads(provisioner.state_path(user).read_text())
                active = False
                with open(f"/run/lock/sservcli-token-{user}.lock", "a") as probe:
                    try:
                        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        active = True
                receipt.update(token_active=active, token_sha256=record.get("last_token_sha256"))
            receipt.update(host_public_key=public, requested_user=preferred)
        print(json.dumps(receipt), flush=True)
        if account_lock:
            # Only the unprivileged controller owns this pipe's write end.
            # EOF revokes the password, including when that controller crashes.
            for _ in sys.stdin:
                pass
        return 0
    finally:
        try:
            if ready:
                with management_lock():
                    provisioner.lock_token(ready["user"], ready["uid"])
        finally:
            if account_lock:
                account_lock.close()


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    for command in ("render", "install", "ensure", "audit", "remove", "token-prepare", "token-serve"):
        sub = commands.add_parser(command)
        if command != "remove":
            sub.add_argument("--config", help="Client JSON profile; only server authorization fields are read")
            sub.add_argument("--permit-open", nargs="+", help="Explicit 127.0.0.1:port allowlist")
        sub.add_argument("--user", help="Dedicated account (default: svc_tunnel)")
        if command in ("install", "ensure"):
            sub.add_argument("--public-key", required=True)
        if command in ("install", "ensure", "token-prepare", "token-serve"):
            sub.add_argument("--ensure-ssh", action="store_true", help="Generate missing host keys and enable/start the SSH service before installing")
        if command in ("token-prepare", "token-serve"):
            sub.add_argument("--host-key", default="/etc/ssh/ssh_host_ed25519_key.pub")
        if command == "token-serve":
            sub.add_argument("--reuse-token-stdin", action="store_true", help="Read a saved token from the private control pipe and verify its managed hash")
            sub.add_argument("--no-reset-token", action="store_true", help="Refuse to rotate an existing token if its private saved value is unavailable")
        if command != "render":
            sub.add_argument("--sshd-config", default="/etc/ssh/sshd_config")
            sub.add_argument("--ssh-service", default="ssh")
            sub.add_argument("--sshd-pid-file", default=os.environ.get("SSHD_PID_FILE") or None,
                             help="Manage a running container sshd through its PID file instead of systemd")
            sub.add_argument("--client-address", default="127.0.0.1", help="Source IP used when auditing Match rules")
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "remove":
            user, permitted = username(args.user or "svc_tunnel"), None
        else:
            user, permitted = policy_input(args)
        if args.command == "render":
            mode = "token" if args.config and json.loads(Path(args.config).read_text()).get("version") == 2 else "key"
            print(policy(user, permitted, mode), end="")
            return 0
        if os.geteuid() != 0:
            raise SetupError("Run account-management commands as root; render does not need root")
        provisioner = Provisioner(args)
        if args.command in ("token-prepare", "token-serve"):
            def stop(*_):
                raise KeyboardInterrupt
            signal.signal(signal.SIGTERM, stop)
            signal.signal(signal.SIGINT, stop)
            signal.signal(signal.SIGHUP, stop)
            return token_command(args, provisioner, user, permitted)
        with management_lock():
            if args.command in ("install", "ensure"):
                if args.ensure_ssh:
                    provisioner.ensure_ssh()
                if args.command == "ensure":
                    # Machine-readable ownership receipt lets the bundler roll
                    # back only accounts created by this invocation, under lock.
                    with contextlib.redirect_stdout(sys.stderr):
                        result = provisioner.ensure(user, permitted, args.public_key)
                    print(json.dumps(result))
                else:
                    provisioner.install(user, permitted, args.public_key)
            elif args.command == "remove":
                provisioner.remove(user)
            else:
                mode = "key"
                if provisioner.state_path(user).exists():
                    safe_file(provisioner.state_path(user))
                    mode = json.loads(provisioner.state_path(user).read_text()).get("auth_mode", "key")
                print(provisioner.audit(user, provisioner.audit_destinations(user, permitted), mode), end="")
        return 0
    except KeyboardInterrupt:
        return 0
    except (SetupError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"sservcli-server: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
