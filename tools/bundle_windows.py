#!/usr/bin/env python3
"""Prepare a Go Windows client ZIP and provision a forwarding account locally.

Token mode prepares a restricted system OpenSSH account and embeds its public
host key. The optional legacy mode registers an existing client public key.
Private keys stay on the server/client. Token bundles include the current startup token as .token.
"""
import argparse
import hashlib
import hmac
import stat
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sservcli.config import ConfigError, load_profile, token_profile, validate_profile, validate_token
from sservcli.token_auth import read_private
server = None
if os.name == "posix":
    spec = importlib.util.spec_from_file_location("sservcli_server", ROOT / "server/sservcli_server.py")
    server = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(server)
LegacySetupError = server.SetupError if server else ConfigError


BundleError = ConfigError


def run(argv, *, timeout=3600, cwd=None, env=None):
    result = subprocess.run([str(arg) for arg in argv], text=True, capture_output=True, timeout=timeout, cwd=cwd, env=env)
    if result.returncode:
        raise BundleError(f"{argv[0]} failed: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout


def source_files(root=ROOT):
    """Explicit runtime allowlist: never walk arbitrary directories or key files."""
    required = ["Build.cmd", "Start.cmd", "Stop.cmd", "README.md", "client/go.mod", "client/cmd/sservcli/main.go", "client/cmd/askpass/main.go",
                "examples/services.token.json", "examples/services.token.windows.json"]
    required += [f"client/internal/app/{name}.go" for name in (
        "config", "tunnel", "daemon", "dashboard", "main", "platform_unix", "platform_windows", "process_linux", "process_other")]
    files = {}
    for name in required:
        path = root / name
        if any(parent.is_symlink() for parent in (path, *[root / parent for parent in path.relative_to(root).parents])):
            raise BundleError(f"Symbolic-linked runtime input: {name}")
        if not path.is_file() or path.stat().st_size > 1024 * 1024:
            raise BundleError(f"Missing or oversized runtime input: {name}")
        data = path.read_bytes()
        if path.suffix == ".cmd":
            data = data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        files[name] = data
    return files


def write_archive(output, files, directory):
    files = dict(files)
    files["SHA256SUMS.txt"] = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in sorted(files.items())).encode()
    archive = Path(directory) / "client.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as stream:
        for name, data in files.items():
            entry = zipfile.ZipInfo(name)
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = (stat.S_IFREG | (0o600 if name == ".token" else 0o644)) << 16
            stream.writestr(entry, data)
    if ".token" in files:
        archive.chmod(0o600)
    # Keep previous downloads and handle competing publishers without clobbering.
    index = 1
    while True:
        candidate = output if index == 1 else output.with_name(f"{output.stem}-{index}{output.suffix}")
        try:
            os.link(archive, candidate)
            break
        except FileExistsError:
            index += 1
    archive.unlink()
    return candidate


def build_client(args):
    if args.source_only:
        return {}
    import shutil
    go = shutil.which("go")
    if not go:
        raise BundleError("Install Go to build the Windows EXE, or use BUILD_CLIENT=0 for a source ZIP")
    binaries = {}
    with tempfile.TemporaryDirectory(prefix="sservcli-go-build-") as temporary:
        environment = {**os.environ, "GOOS": "windows", "GOARCH": args.arch, "CGO_ENABLED": "0", "GOWORK": "off"}
        for name, package, flags in (("sservcli.exe", "./cmd/sservcli", "-s -w"),
                                     ("sservcli-askpass.exe", "./cmd/askpass", "-s -w -H=windowsgui")):
            output = Path(temporary) / name
            run([go, "build", "-trimpath", "-ldflags=" + flags, "-o", output, package],
                cwd=ROOT / "client", env=environment)
            data = output.read_bytes()
            if not data.startswith(b"MZ"):
                raise BundleError("Go did not produce a Windows executable")
            binaries[name] = data
    return binaries


def client_archive(config, inputs, token=None):
    validate_profile(config)
    files = {**inputs, "services.json": (json.dumps(config, indent=2) + "\n").encode(),
             "README.txt": ("sservcli Go Windows client\r\n\r\n"
                "Extract the entire ZIP under your Windows user account. Enable Windows OpenSSH Client.\r\n"
                "A bundled sservcli.exe needs neither Python nor Go installed.\r\n"
                "If the EXE is absent, install Go and run Build.cmd once.\r\n"
                + ("The current case-sensitive 8-character startup token is included in .token beside sservcli.exe.\r\n" if config["version"] == 2 else
                   "This key/Agent profile uses your existing authorized private key.\r\n") +
                "Run Start.cmd. All enabled services forward in the background.\r\n"
                "Open http://127.0.0.1:8000 for status, service addresses, connect/disconnect, and configuration.\r\n"
                "Run Stop.cmd or sservcli.exe stop to release all forwards. Closing the browser keeps SSH running.\r\n"
                "sservcli.exe list shows the service catalog. services.json and .token are read beside the EXE.\r\n"
                "Keep this ZIP private: .token grants forwarding access. Restarting make server requires a new token/ZIP.\r\n"
                "No private keys or Python files are included. See README.md for details.\r\n").encode()}
    if config["version"] == 2:
        files[".token"] = (validate_token(token) + "\n").encode("ascii")
    if config["ssh"].get("host_public_key"):
        files["server-host-key.pub"] = (config["ssh"]["host_public_key"].strip() + "\n").encode()
    return files


def archive_inputs(args):
    inputs = source_files()
    if not args.dry_run:
        executable = build_client(args)
        if executable:
            inputs.update(executable)
    return inputs


def server_command(args, operation, profile=None):
    command = [sys.executable, ROOT / "server/sservcli_server.py", operation,
               "--sshd-config", args.sshd_config, "--ssh-service", args.ssh_service]
    if operation == "token-prepare":
        command += ["--config", profile, "--host-key", args.host_key, "--ensure-ssh"]
    elif operation == "ensure":
        command += ["--config", profile, "--public-key", args.public_key, "--ensure-ssh"]
    else:
        command += ["--user", args.user]
    return command if os.geteuid() == 0 else ["sudo", *command]


def profile_for(args):
    config = json.loads(args.config.read_text(encoding="utf-8"))
    if not isinstance(config, dict) or not isinstance(config.get("ssh"), dict):
        raise BundleError("CONFIG must contain a client profile with an ssh object")
    ssh = config["ssh"]
    args.host, args.user = ssh.get("host"), ssh.get("user")
    if not args.host or args.host == "server.example.com":
        raise BundleError("Set ssh.host in CONFIG to the server's real reachable IP or hostname")
    if not isinstance(args.user, str):
        raise BundleError("Set ssh.user in CONFIG to the forwarding account name")
    server.username(args.user)
    ssh["known_hosts_file"] = "unused-during-validation"
    config["ssh"].pop("host_public_key", None)
    validate_profile(config)
    # Match the generated server account policy to exactly these destinations.
    permitted = server.destinations([f'{service["remote_host"]}:{service["remote_port"]}' for service in config["services"]])
    server.restricted_key(args.public_key.read_text(encoding="utf-8"), permitted)
    return config


def package(args):
    if not args.config.is_file():
        raise BundleError("Set CONFIG to an existing services JSON (copy and edit examples/services.token.json)")
    if not args.client_only and not args.legacy_ssh:
        return package_token(args)
    if args.legacy_ssh and server is None:
        raise BundleError("Account provisioning requires Ubuntu/OpenSSH; use --client-only to repackage a final profile elsewhere")
    if not args.client_only and (not args.public_key or not args.public_key.is_file()):
        raise BundleError("Set PUBKEY_FILE to the existing Windows client's Ed25519 PUBLIC key; private keys are never packaged")
    if args.client_only:
        config = load_profile(args.config)
        output = (args.output or ROOT / "dist/sservcli-windows-go.zip").absolute()
        token = bundle_token(args, config) if not args.dry_run else None
        inputs = archive_inputs(args)
        if args.dry_run:
            print("Dry run: client profile and Go client source files validated; would publish:", output)
            return None
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".sservcli-client-", dir=output.parent) as directory:
            output = write_archive(output, client_archive(config, inputs, token), directory)
        print("Go client ZIP ready:", output)
        return output
    config = profile_for(args)
    output = (args.output or ROOT / f"dist/sservcli-windows-{args.user}-go.zip").absolute()
    output.parent.mkdir(parents=True, exist_ok=True)
    created = False
    with tempfile.TemporaryDirectory(prefix=".sservcli-bundle-", dir=output.parent) as scratch:
        directory = Path(scratch)
        inputs = archive_inputs(args)
        # Validate and gather build inputs before privileged account changes.
        policy_profile = directory / "server-policy.json"
        policy_profile.write_text(json.dumps(config), encoding="utf-8")
        if args.dry_run:
            print("Dry run: configuration, public key, and archive inputs validated; would generate missing host keys, start SSH, create/reuse the account, register a missing key for managed accounts, and publish (adding a suffix if the ZIP exists):", output)
            print("Account:", args.user, "Addresses:", [config["ssh"]["host"], *config["ssh"].get("fallback_hosts", [])])
            return None
        try:
            print(f"Preparing forwarding account {args.user} with the supplied client public key", flush=True)
            receipt = json.loads(run(server_command(args, "ensure", policy_profile)))
            if (not isinstance(receipt, dict) or receipt.get("user") != args.user
                    or type(receipt.get("created")) is not bool
                    or receipt.get("account") not in ("created", "reused", "external")
                    or receipt["created"] != (receipt["account"] == "created")
                    or receipt.get("key") not in ("added", "updated", "unchanged")):
                raise BundleError("Invalid account setup receipt; refusing automatic account cleanup")
            created = receipt["created"]
            print(f"Account: {receipt['account']}; public key: {receipt['key']}")
            if receipt.get("message"):
                print(receipt["message"])
            host_key = args.host_key.read_text(encoding="utf-8").strip()
            run(["ssh-keygen", "-lf", args.host_key])
            # Only public host-key material enters the ZIP.
            if not re.fullmatch(r"(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) [A-Za-z0-9+/=]+(?: [^\r\n]*)?", host_key):
                raise BundleError("Expected one plain server host public key")
            config["ssh"].pop("known_hosts_file", None)
            config["ssh"]["host_public_key"] = " ".join(host_key.split()[:2])
            validate_profile(config)
            output = write_archive(output, client_archive(config, inputs), directory)
        except BaseException:
            if created:
                print("Bundle failed after account creation; attempting to remove the newly created managed account", file=sys.stderr)
                try:
                    run(server_command(args, "remove"))
                except (BundleError, OSError) as error:
                    print(f"Account rollback failed; administrator recovery required: {error}", file=sys.stderr)
            raise
    print(f"Windows bundle ready: {output}\nDownload this ZIP to Windows, extract it, and run Start.cmd (Windows OpenSSH Client required). No client private key was copied.")
    return output


def bundle_token(args, config):
    if config["version"] != 2:
        return None
    adjacent = args.config.parent / ".token"
    path = args.token_file or (adjacent if args.client_only and adjacent.exists() else args.state_dir / "access.token")
    try:
        return validate_token(read_private(path).rstrip("\r\n"))
    except (OSError, ValueError) as error:
        raise BundleError(f"Cannot read current token from {path}; keep make server running or set BUNDLE_TOKEN_FILE to a private token file") from error


def package_token(args):
    config = token_profile(load_profile(args.config), args.token_port)
    if config["ssh"]["host"] == "server.example.com":
        raise BundleError("Set ssh.host in CONFIG to the server's reachable IP or hostname")
    token = bundle_token(args, config) if not args.dry_run else None
    inputs = archive_inputs(args)
    output = (args.output or ROOT / "dist/sservcli-windows-token.zip").absolute()
    if args.dry_run:
        print("Dry run: would create/reuse a restricted OpenSSH password account and pin the existing sshd public host key.")
        print("Would publish:", output, "(numeric suffix if it exists). The current running token will be included as .token; no new token is issued.")
        return None
    if server is None:
        raise BundleError("Prepare the server account on Ubuntu/OpenSSH; use --client-only to repackage a final client profile elsewhere")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".sservcli-token-bundle-", dir=output.parent) as directory:
        profile_path = Path(directory) / "policy.json"
        profile_path.write_text(json.dumps(config), encoding="utf-8")
        receipt = json.loads(run(server_command(args, "token-prepare", profile_path)))
        if not isinstance(receipt, dict) or not isinstance(receipt.get("user"), str) or not isinstance(receipt.get("host_public_key"), str):
            raise BundleError("Invalid OpenSSH preparation response")
        if (receipt.get("token_active") is not True or not isinstance(receipt.get("token_sha256"), str)
                or not hmac.compare_digest(receipt["token_sha256"], hashlib.sha256(token.encode()).hexdigest())):
            raise BundleError("No matching active startup token. Keep make server running with the same CONFIG/SERVER_STATE, then run bundle again")
        server.username(receipt["user"])
        config["ssh"].update(user=receipt["user"], host_public_key=receipt["host_public_key"])
        validate_profile(config)
        output = write_archive(output, client_archive(config, inputs, token), directory)
    print(f"OpenSSH token client ZIP ready: {output}\nThe current startup token is included as .token. Extract the whole ZIP and run Start.cmd on Windows.")
    return output


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    env = os.environ
    default_config = Path(env.get("CONFIG") or "services.json")
    result.add_argument("--config", type=Path, default=default_config)
    result.add_argument("--public-key", type=Path, default=Path(env["PUBKEY_FILE"]) if env.get("PUBKEY_FILE") else None)
    result.add_argument("--host-key", type=Path, default=Path(env.get("HOST_KEY_FILE") or "/etc/ssh/ssh_host_ed25519_key.pub"))
    result.add_argument("--client-only", action="store_true", help="Package an existing client profile without account changes or PUBKEY_FILE")
    result.add_argument("--legacy-ssh", action="store_true", default=env.get("LEGACY_SSH") == "1", help="Use the old OS-account/public-key provisioning workflow")
    result.add_argument("--token-file", type=Path, default=Path(env["BUNDLE_TOKEN_FILE"]) if env.get("BUNDLE_TOKEN_FILE") else None,
                        help="Current token to include; defaults to SERVER_STATE/access.token (client-only also checks adjacent .token)")
    result.add_argument("--source-only", action="store_true", default=env.get("BUILD_CLIENT") == "0", help="Package Go sources without compiling an EXE")
    result.add_argument("--arch", choices=("amd64", "arm64"), default=env.get("WINDOWS_ARCH") or "amd64")
    result.add_argument("--state-dir", type=Path, default=Path(env.get("SERVER_STATE") or ROOT / "var/server"))
    result.add_argument("--token-port", type=int, default=int(env["TOKEN_PORT"]) if env.get("TOKEN_PORT") else None)
    result.add_argument("--output", type=Path, default=Path(env["BUNDLE_OUTPUT"]) if env.get("BUNDLE_OUTPUT") else None)
    result.add_argument("--sshd-config", default=env.get("SSHD_CONFIG", "/etc/ssh/sshd_config"))
    result.add_argument("--ssh-service", default=env.get("SSH_SERVICE", "ssh"))
    result.add_argument("--dry-run", action="store_true", default=env.get("DRY_RUN") == "1")
    return result


if __name__ == "__main__":
    try:
        package(parser().parse_args())
    except (BundleError, LegacySetupError, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired, zipfile.BadZipFile) as error:
        print(f"sservcli-bundle: {error}", file=sys.stderr)
        sys.exit(1)
