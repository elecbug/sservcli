#!/usr/bin/env python3
"""Provision an Ubuntu/OpenSSH forwarding account; no custom server daemon."""
import argparse
import contextlib
import fcntl
import hashlib
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
        if type(config.get("version")) is not int or config["version"] != 1:
            raise SetupError("Only configuration version 1 is supported")
        user = config["ssh"]["user"]
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


def policy(user, permitted):
    begin, end = markers(user)
    options = {**POLICY, "PermitOpen": " ".join(permitted),
               "AuthorizedKeysFile": f"/home/{user}/.ssh/authorized_keys"}
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
        self.context = f"host=localhost,addr={args.client_address}"
        if not re.fullmatch(r"[0-9a-fA-F:.]+", args.client_address):
            raise SetupError("--client-address must be an IP address")

    def syntax(self):
        run([self.sshd, "-t", "-f", str(self.config)])

    def audit(self, user, permitted):
        self.syntax()
        result = run([self.sshd, "-T", "-f", str(self.config), "-C", f"user={user},{self.context}"])
        effective = dict(line.split(" ", 1) for line in result.stdout.splitlines() if " " in line)
        expected = {**POLICY, "PermitOpen": " ".join(permitted),
                    "AuthorizedKeysFile": f"/home/{user}/.ssh/authorized_keys"}
        for key, value in expected.items():
            actual = effective.get(key.lower())
            if actual != value:
                raise SetupError(f"Effective {key} is {actual!r}, expected {value!r}; inspect earlier Match/Include rules")
        if effective.get("disableforwarding") == "yes":
            raise SetupError("DisableForwarding prevents the configured tunnels")
        return result.stdout

    def reload(self):
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

    def bind_key(self, user, permitted, key_path):
        """Reuse a managed identity; never delete it when an update fails."""
        safe_directory(self.state_dir)
        state_path = self.state_path(user)
        state_info = safe_file(state_path)
        state_original = state_path.read_text()
        record = json.loads(state_original)
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


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    for command in ("render", "install", "ensure", "audit", "remove"):
        sub = commands.add_parser(command)
        if command != "remove":
            sub.add_argument("--config", help="Client JSON profile; only server authorization fields are read")
            sub.add_argument("--permit-open", nargs="+", help="Explicit 127.0.0.1:port allowlist")
        sub.add_argument("--user", help="Dedicated account (default: svc_tunnel)")
        if command in ("install", "ensure"):
            sub.add_argument("--public-key", required=True)
            sub.add_argument("--ensure-ssh", action="store_true", help="Generate missing host keys and enable/start the SSH service before installing")
        if command != "render":
            sub.add_argument("--sshd-config", default="/etc/ssh/sshd_config")
            sub.add_argument("--ssh-service", default="ssh")
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
            print(policy(user, permitted), end="")
            return 0
        if os.geteuid() != 0:
            raise SetupError("Run install/ensure/audit/remove as root; render does not need root")
        provisioner = Provisioner(args)
        with open("/run/lock/sservcli.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if args.command in ("install", "ensure"):
                if args.ensure_ssh:
                    run(["ssh-keygen", "-A"])
                    run(["systemctl", "enable", "--now", provisioner.service])
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
                print(provisioner.audit(user, provisioner.audit_destinations(user, permitted)), end="")
        return 0
    except (SetupError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"sservcli-server: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
