#!/usr/bin/env python3
"""Prepare a Python Windows client ZIP and provision a forwarding account locally.

Existing client private keys stay on Windows. This tool registers only the supplied
client public key and embeds only the server's public host key in the bundle.
"""
import argparse
import hashlib
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
from sservcli.config import ConfigError, load_profile, validate_profile
spec = importlib.util.spec_from_file_location("sservcli_server", ROOT / "server/sservcli_server.py")
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)


BundleError = ConfigError


def run(argv, *, timeout=3600):
    result = subprocess.run([str(arg) for arg in argv], text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise BundleError(f"{argv[0]} failed: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout


def source_files(root=ROOT):
    """Explicit runtime allowlist: never walk arbitrary directories or key files."""
    required = ["Build.cmd", "Start.cmd", "README.md", "client/examples/services.json", "client/examples/services.windows.json"]
    required += [f"sservcli/{name}.py" for name in (
        "__init__", "__main__", "config", "tunnel", "desktop", "instance", "windows", "windows_launcher")]
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
            stream.writestr(name, data)
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


def client_archive(config, inputs):
    validate_profile(config)
    files = {**inputs, "services.json": (json.dumps(config, indent=2) + "\n").encode(),
             "README.txt": ("sservcli Python Windows client\r\n\r\n"
                "Extract the entire ZIP under your Windows user account.\r\n"
                "Install Python 3.11+ with Tcl/Tk and the Python launcher, and enable Windows OpenSSH Client.\r\n"
                "Run Start.cmd. Build.cmd only checks prerequisites; compilation and pip install are not required.\r\n"
                "Use the private key or SSH Agent matching the client public key authorized on the server.\r\n"
                "All enabled services connect automatically. Click the tray icon to show services. Tray > Quit stops SSH.\r\n"
                "Closing the window keeps forwarding in the Windows tray; on other platforms it minimizes the window.\r\n"
                "services.json supplies the host key, fallback addresses, services, and client identity path.\r\n"
                "No private keys or passwords are included. See README.md for configuration and troubleshooting.\r\n").encode()}
    if config["ssh"].get("host_public_key"):
        files["server-host-key.pub"] = (config["ssh"]["host_public_key"].strip() + "\n").encode()
    return files


def server_command(args, operation, profile=None):
    command = [sys.executable, ROOT / "server/sservcli_server.py", operation,
               "--sshd-config", args.sshd_config, "--ssh-service", args.ssh_service]
    if operation == "ensure":
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
        raise BundleError("Set CONFIG to an existing services JSON (copy and edit client/examples/services.json)")
    if not args.client_only and (not args.public_key or not args.public_key.is_file()):
        raise BundleError("Set PUBKEY_FILE to the existing Windows client's Ed25519 PUBLIC key; private keys are never packaged")
    if args.client_only:
        config = load_profile(args.config)
        output = (args.output or ROOT / "dist/sservcli-windows-python.zip").absolute()
        inputs = source_files()
        if args.dry_run:
            print("Dry run: client profile and Python runtime files validated; would publish:", output)
            return None
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".sservcli-client-", dir=output.parent) as directory:
            output = write_archive(output, client_archive(config, inputs), directory)
        print("Python client ZIP ready:", output)
        return output
    config = profile_for(args)
    output = (args.output or ROOT / f"dist/sservcli-windows-{args.user}-python.zip").absolute()
    output.parent.mkdir(parents=True, exist_ok=True)
    created = False
    with tempfile.TemporaryDirectory(prefix=".sservcli-bundle-", dir=output.parent) as scratch:
        directory = Path(scratch)
        inputs = source_files()
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
    print(f"Windows bundle ready: {output}\nDownload this ZIP to Windows, extract it, and run Start.cmd (Python 3.11+ with Tkinter and OpenSSH Client required). No client private key was copied.")
    return output


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    env = os.environ
    default_config = Path(env.get("CONFIG") or "services.json")
    result.add_argument("--config", type=Path, default=default_config)
    result.add_argument("--public-key", type=Path, default=Path(env["PUBKEY_FILE"]) if env.get("PUBKEY_FILE") else None)
    result.add_argument("--host-key", type=Path, default=Path(env.get("HOST_KEY_FILE") or "/etc/ssh/ssh_host_ed25519_key.pub"))
    result.add_argument("--client-only", action="store_true", help="Package an existing client profile without account changes or PUBKEY_FILE")
    result.add_argument("--output", type=Path, default=Path(env["BUNDLE_OUTPUT"]) if env.get("BUNDLE_OUTPUT") else None)
    result.add_argument("--sshd-config", default=env.get("SSHD_CONFIG", "/etc/ssh/sshd_config"))
    result.add_argument("--ssh-service", default=env.get("SSH_SERVICE", "ssh"))
    result.add_argument("--dry-run", action="store_true", default=env.get("DRY_RUN") == "1")
    return result


if __name__ == "__main__":
    try:
        package(parser().parse_args())
    except (BundleError, server.SetupError, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired, zipfile.BadZipFile) as error:
        print(f"sservcli-bundle: {error}", file=sys.stderr)
        sys.exit(1)
