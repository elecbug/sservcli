#!/usr/bin/env python3
"""Build/fetch Windows binaries, provision a forwarding account, and publish a ZIP.

Existing client private keys stay on Windows. This tool registers only the supplied
client public key and embeds only the server's public host key in the bundle.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sservcli_server", ROOT / "server/sservcli_server.py")
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)


class BundleError(Exception):
    pass


def run(argv, *, timeout=3600):
    result = subprocess.run([str(arg) for arg in argv], text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise BundleError(f"{argv[0]} failed: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout


def validate_pe(data, name):
    if len(data) < 64 or data[:2] != b"MZ":
        raise BundleError(f"{name} is not a Windows executable")
    offset = struct.unpack_from("<I", data, 60)[0]
    if offset + 26 > len(data) or data[offset:offset + 4] != b"PE\0\0" or struct.unpack_from("<H", data, offset + 4)[0] != 0x8664:
        raise BundleError(f"{name} must be a native Windows x64 executable")


def read_binaries(source):
    wanted = {"sservcli.exe", "sservcli-desktop.exe"}
    found = {}
    limit = 150 * 1024 * 1024
    def add(name, data):
        if name in found:
            raise BundleError(f"Duplicate binary in artifact: {name}")
        validate_pe(data, name)
        found[name] = data
    if source.is_dir():
        for path in source.rglob("*.exe"):
            if path.name in wanted:
                if path.is_symlink() or path.stat().st_size > limit:
                    raise BundleError(f"Unsafe or oversized binary: {path}")
                add(path.name, path.read_bytes())
    else:
        with zipfile.ZipFile(source) as archive:
            for info in archive.infolist():
                path = PurePosixPath(info.filename)
                if path.is_absolute() or ".." in path.parts or "\\" in info.filename:
                    raise BundleError("Artifact contains an unsafe ZIP path")
                if path.name in wanted:
                    if info.file_size > limit or stat.S_ISLNK(info.external_attr >> 16):
                        raise BundleError("Artifact contains an oversized binary or symbolic link")
                    add(path.name, archive.read(info))
    if found.keys() != wanted:
        raise BundleError("Windows artifact must contain sservcli.exe and sservcli-desktop.exe")
    return found


def fetch_binaries(directory, repo=None, ref=None):
    if not shutil.which("gh"):
        raise BundleError("Install/authenticate GitHub CLI (gh auth login), or set WINDOWS_ARTIFACT to a native binary ZIP/directory")
    repo = repo or json.loads(run(["gh", "repo", "view", "--json", "nameWithOwner"]))["nameWithOwner"]
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", repo):
        raise BundleError("Invalid GitHub repository")
    ref = ref or run(["git", "branch", "--show-current"]).strip()
    if not ref or ref.startswith("-"):
        raise BundleError("Set WINDOWS_REF to a pushed branch or tag")
    local_sha = run(["git", "rev-parse", "HEAD"]).strip()
    if run(["git", "status", "--porcelain", "--untracked-files=normal"]).strip():
        raise BundleError("Commit and push source changes before building on GitHub, or provide WINDOWS_ARTIFACT explicitly")
    remote_sha = json.loads(run(["gh", "api", f"repos/{repo}/commits/{ref}"]))["sha"]
    if remote_sha != local_sha:
        raise BundleError("The selected remote ref differs from local HEAD; push the intended source before building")
    request_id = uuid.uuid4().hex
    title = f"Windows binaries {request_id}"
    print(f"Requesting native Windows build for {repo}@{ref} ({local_sha[:12]})", flush=True)
    run(["gh", "workflow", "run", "windows-binaries.yml", "--repo", repo, "--ref", ref, "-f", f"request_id={request_id}"])
    run_id = None
    for _ in range(60):
        candidates = json.loads(run(["gh", "run", "list", "--repo", repo, "--workflow", "windows-binaries.yml", "--event", "workflow_dispatch", "--limit", "100", "--json", "databaseId,displayTitle,headSha"]))
        match = next((item for item in candidates if item["displayTitle"] == title and item["headSha"] == local_sha), None)
        if match:
            run_id = str(match["databaseId"])
            break
        time.sleep(2)
    if not run_id:
        raise BundleError("Could not identify the dispatched Windows build; server provisioning has not started")
    print(f"Waiting for Windows build: https://github.com/{repo}/actions/runs/{run_id}\nNo SSH keys or server configuration are uploaded", flush=True)
    run(["gh", "run", "watch", run_id, "--repo", repo, "--exit-status"])
    run(["gh", "run", "download", run_id, "--repo", repo, "--name", "sservcli-windows-binaries", "--dir", directory])
    return directory


def validate_profile(config, validator, directory):
    path = directory / "validate-profile.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    run([validator, "check", "--config", path])


def server_command(args, operation, profile=None):
    command = [sys.executable, ROOT / "server/sservcli_server.py", operation,
               "--sshd-config", args.sshd_config, "--ssh-service", args.ssh_service]
    if operation == "install":
        command += ["--config", profile, "--public-key", args.public_key, "--ensure-ssh"]
    else:
        command += ["--user", args.user]
    return command if os.geteuid() == 0 else ["sudo", *command]


def profile_for(args):
    config = json.loads(args.config.read_text(encoding="utf-8"))
    config["ssh"].update({"host": args.host, "user": server.username(args.user),
                          "identity_file": args.client_identity or None, "known_hosts_file": "unused-during-validation"})
    config["ssh"].pop("host_public_key", None)
    if args.fallback_hosts is not None:
        hosts = json.loads(args.fallback_hosts)
        if not isinstance(hosts, list) or not all(isinstance(host, str) for host in hosts):
            raise BundleError("FALLBACK_HOSTS must be a JSON array of IP/hostname strings")
        config["ssh"]["fallback_hosts"] = hosts
    if args.port is not None:
        config["ssh"]["port"] = args.port
    # Match the generated server account policy to exactly these destinations.
    permitted = server.destinations([f'{service["remote_host"]}:{service["remote_port"]}' for service in config["services"]])
    server.restricted_key(args.public_key.read_text(encoding="utf-8"), permitted)
    return config


def package(args):
    if not args.host or args.host == "server.example.com":
        raise BundleError("Set SERVER_HOST to the server's real reachable IP or hostname")
    if not args.public_key or not args.public_key.is_file():
        raise BundleError("Set PUBKEY_FILE to the existing Windows client's Ed25519 PUBLIC key; private keys are never packaged")
    server.username(args.user)
    if server.account(args.user) or os.path.lexists(f"/home/{args.user}"):
        raise BundleError("Account or home already exists; choose a new TUNNEL_USER or administer the existing managed account explicitly")
    if not args.validator.is_file():
        raise BundleError("Build the native validator first (make build), or pass --validator")
    output = args.output.absolute()
    if output.exists():
        raise BundleError(f"Output already exists; choose a new BUNDLE_OUTPUT: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    created = False
    with tempfile.TemporaryDirectory(prefix=".sservcli-bundle-", dir=output.parent) as scratch:
        directory = Path(scratch)
        config = profile_for(args)
        validate_profile(config, args.validator, directory)
        if args.dry_run and not args.windows_artifact:
            print("Dry run: profile/key validated. Would request a native Windows build, then provision", args.user, "and publish", output)
            print("No GitHub workflow, SSH service, or account was changed.")
            return None
        source = args.windows_artifact or fetch_binaries(directory / "native", args.repo, args.ref)
        binaries = read_binaries(source)
        # All validation and native builds precede privileged account changes.
        policy_profile = directory / "server-policy.json"
        policy_profile.write_text(json.dumps(config), encoding="utf-8")
        if args.dry_run:
            print("Dry run: native binaries/profile validated; would generate missing host keys, start SSH, create account, register the client public key, and publish:", output)
            print("Account:", args.user, "Addresses:", [config["ssh"]["host"], *config["ssh"].get("fallback_hosts", [])])
            return None
        try:
            print(f"Provisioning forwarding account {args.user} with the supplied client public key", flush=True)
            print(run(server_command(args, "install", policy_profile)), end="")
            created = True
            host_key = args.host_key.read_text(encoding="utf-8").strip()
            run(["ssh-keygen", "-lf", args.host_key])
            # Only public host-key material enters the ZIP.
            if not re.fullmatch(r"(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) [A-Za-z0-9+/=]+(?: [^\r\n]*)?", host_key):
                raise BundleError("Expected one plain server host public key")
            config["ssh"].pop("known_hosts_file", None)
            config["ssh"]["host_public_key"] = " ".join(host_key.split()[:2])
            validate_profile(config, args.validator, directory)
            files = {**binaries, "services.json": (json.dumps(config, indent=2) + "\n").encode(),
                     "server-host-key.pub": (host_key + "\n").encode(),
                     "Start.cmd": b'@echo off\r\nsetlocal DisableDelayedExpansion\r\nstart "" "%~dp0sservcli-desktop.exe" --config "%~dp0services.json"\r\nendlocal\r\n',
                     "README.txt": ("sservcli Windows client\r\n\r\nExtract this entire ZIP into a folder under your Windows user account, then run Start.cmd.\r\n"
                                    "OpenSSH Client and WebView2 must be installed. Use the existing private key/SSH Agent matching the public key registered on the server.\r\n"
                                    "No private keys or passwords are included. Services connect automatically; close the window to keep forwarding in the tray. Use tray > Quit to stop.\r\n"
                                    "services.json contains the server's pinned public host key, ordered fallback addresses, and local service ports.\r\n").encode()}
            files["SHA256SUMS.txt"] = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in files.items()).encode()
            archive = directory / "client.zip"
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as stream:
                for name, data in files.items():
                    stream.writestr(name, data)
            os.replace(archive, output)
        except BaseException:
            if created:
                print("Bundle failed after account creation; attempting to remove the newly created managed account", file=sys.stderr)
                try:
                    run(server_command(args, "remove"))
                except (BundleError, OSError) as error:
                    print(f"Account rollback failed; administrator recovery required: {error}", file=sys.stderr)
            raise
    print(f"Windows bundle ready: {output}\nDownload this ZIP to Windows, extract it, and run Start.cmd. No client private key was copied.")
    return output


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    env = os.environ
    default_config = Path(env.get("CONFIG", "services.json"))
    if default_config == Path("services.json") and not default_config.exists():
        default_config = ROOT / "client/examples/services.json"
    result.add_argument("--config", type=Path, default=default_config)
    result.add_argument("--host", default=env.get("SERVER_HOST"))
    result.add_argument("--fallback-hosts", default=env.get("FALLBACK_HOSTS"))
    result.add_argument("--port", type=int, default=int(env["SERVER_PORT"]) if env.get("SERVER_PORT") else None)
    result.add_argument("--user", default=env.get("TUNNEL_USER", "svc_tunnel"))
    result.add_argument("--public-key", type=Path, default=Path(env["PUBKEY_FILE"]) if env.get("PUBKEY_FILE") else None)
    result.add_argument("--client-identity", default=env.get("CLIENT_IDENTITY"))
    result.add_argument("--host-key", type=Path, default=Path(env.get("HOST_KEY_FILE") or "/etc/ssh/ssh_host_ed25519_key.pub"))
    result.add_argument("--windows-artifact", type=Path, default=Path(env["WINDOWS_ARTIFACT"]) if env.get("WINDOWS_ARTIFACT") else None)
    result.add_argument("--repo", default=env.get("WINDOWS_REPO"))
    result.add_argument("--ref", default=env.get("WINDOWS_REF"))
    result.add_argument("--validator", type=Path, default=ROOT / "target/release/sservcli")
    result.add_argument("--output", type=Path, default=Path(env.get("BUNDLE_OUTPUT") or f'dist/sservcli-windows-{env.get("TUNNEL_USER", "svc_tunnel")}.zip'))
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
