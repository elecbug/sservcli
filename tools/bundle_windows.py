#!/usr/bin/env python3
"""Prepare a Windows source ZIP and provision a forwarding account locally.

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
import stat
import struct
import subprocess
import sys
import tempfile
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


def validate_profile(config):
    """Validate the client schema without requiring a Rust build on the server."""
    def fields(value, allowed, required, label):
        if not isinstance(value, dict) or set(value) - set(allowed) or set(required) - set(value):
            raise BundleError(f"Invalid or unknown fields in {label}")
    def number(value, low, high, label):
        if type(value) is not int or not low <= value <= high:
            raise BundleError(f"{label} must be an integer between {low} and {high}")
    def control(value):
        return any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value)
    def path(value):
        if not isinstance(value, str) or not value or control(value) or '"' in value or '%' in value:
            raise BundleError("SSH paths must be nonempty and contain no controls, quotes, or % tokens")
    identifier = re.compile(r"[A-Za-z0-9_-]{1,64}")
    fields(config, ("version", "name", "ssh", "reconnect", "services"), ("version", "name", "ssh", "services"), "profile")
    if type(config["version"]) is not int or config["version"] != 1:
        raise BundleError("Only profile version 1 is supported")
    if not isinstance(config["name"], str) or not config["name"].strip() or len(config["name"].encode()) > 128:
        raise BundleError("Profile name must contain 1-128 UTF-8 bytes")
    ssh = config["ssh"]
    fields(ssh, ("host", "fallback_hosts", "port", "user", "identity_file", "known_hosts_file", "host_public_key"), ("host", "user"), "ssh")
    fallback = ssh.get("fallback_hosts", [])
    if not isinstance(fallback, list):
        raise BundleError("ssh.fallback_hosts must be an array")
    hosts = [ssh["host"], *fallback]
    if len(hosts) > 16 or any(not isinstance(host, str) or len(host) > 253 or host.startswith("-") or not re.fullmatch(r"[A-Za-z0-9.:-]+", host) for host in hosts):
        raise BundleError("Configure at most 16 valid SSH hostnames/IPs")
    if len(set(host.lower() for host in hosts)) != len(hosts):
        raise BundleError("SSH addresses must be unique")
    if not isinstance(ssh["user"], str) or not identifier.fullmatch(ssh["user"]) or ssh["user"].startswith("-"):
        raise BundleError("Invalid SSH username")
    number(ssh.get("port", 22), 1, 65535, "ssh.port")
    if ssh.get("identity_file") is not None:
        path(ssh["identity_file"])
    if (ssh.get("host_public_key") is None) == (ssh.get("known_hosts_file") is None):
        raise BundleError("Set exactly one host-key verification source")
    if ssh.get("known_hosts_file") is not None:
        path(ssh["known_hosts_file"])
    if ssh.get("host_public_key") is not None:
        key = ssh["host_public_key"]
        if not isinstance(key, str) or len(key.strip().encode()) > 16384 or '\n' in key.strip() or '\r' in key.strip() or not re.fullmatch(r"(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521))\s+[A-Za-z0-9+/=]{16,}(?:\s+[^\r\n]*)?", key.strip()):
            raise BundleError("Expected one plain server host public key")
    reconnect = config.get("reconnect", {})
    fields(reconnect, ("enabled", "max_attempts", "initial_delay_secs", "max_delay_secs"), (), "reconnect")
    if type(reconnect.get("enabled", True)) is not bool:
        raise BundleError("reconnect.enabled must be a boolean")
    number(reconnect.get("max_attempts", 5), 0, 100, "reconnect.max_attempts")
    delay = reconnect.get("initial_delay_secs", 2)
    number(delay, 1, 300, "reconnect.initial_delay_secs")
    number(reconnect.get("max_delay_secs", 30), delay, 300, "reconnect.max_delay_secs")
    services = config["services"]
    if not isinstance(services, list) or not 1 <= len(services) <= 64:
        raise BundleError("Configure 1-64 services")
    ids, ports = set(), set()
    for service in services:
        fields(service, ("id", "name", "kind", "remote_host", "remote_port", "local_port", "enabled", "path", "scheme", "launch"), ("id", "name", "kind", "remote_host", "remote_port", "local_port"), "service")
        if not isinstance(service["id"], str) or not identifier.fullmatch(service["id"]) or service["id"] in ids or not isinstance(service["name"], str) or not service["name"].strip():
            raise BundleError("Services need unique ids and nonempty names")
        ids.add(service["id"])
        if service["kind"] not in ("web", "api", "database", "tcp") or service["remote_host"] != "127.0.0.1":
            raise BundleError("Invalid service kind or remote_host")
        number(service["remote_port"], 1, 65535, "remote_port")
        number(service["local_port"], 1024, 65535, "local_port")
        if service["local_port"] in ports or type(service.get("enabled", True)) is not bool:
            raise BundleError("Local ports must be unique and enabled must be a boolean")
        ports.add(service["local_port"])
        url_path = service.get("path", "/")
        if not isinstance(url_path, str) or not url_path.startswith("/") or url_path.startswith("//") or control(url_path) or any(c.isspace() or c == '\\' for c in url_path) or service.get("scheme", "http") not in ("http", "https"):
            raise BundleError("Invalid service URL path or scheme")
        launch = service.get("launch")
        if launch is not None:
            if not isinstance(launch, list) or not launch or any(not isinstance(arg, str) or '\0' in arg for arg in launch) or not launch[0] or launch[0].startswith("-") or any(c in launch[0] for c in "{}"):
                raise BundleError("Invalid launch executable/argument array")
            for arg in launch[1:]:
                rest = arg.replace("{host}", "").replace("{port}", "").replace("{url}", "")
                if '{' in rest or '}' in rest:
                    raise BundleError("Unknown launch placeholder")


def source_files(root=ROOT):
    """Explicit build-input allowlist; never archive keys, .git, caches or outputs."""
    required = ["Cargo.toml", "Cargo.lock", "client/Cargo.toml", "client/desktop/package.json", "client/desktop/package-lock.json",
                "client/desktop/src-tauri/Cargo.toml", "client/desktop/src-tauri/Cargo.lock", "client/desktop/src-tauri/build.rs", "client/desktop/src-tauri/tauri.conf.json"]
    directories = {"client/src": {".rs"}, "client/examples": {".json"}, "client/desktop/ui": {".html", ".css", ".js", ".svg", ".png", ".ico", ".woff2"},
                   "client/desktop/src-tauri/src": {".rs"}, "client/desktop/src-tauri/capabilities": {".json"}, "client/desktop/src-tauri/icons": {".png", ".ico", ".svg"}}
    paths = [root / name for name in required]
    for name, extensions in directories.items():
        directory = root / name
        if directory.is_symlink() or not directory.is_dir():
            raise BundleError(f"Missing or symbolic-linked source directory: {name}")
        paths += [path for path in directory.rglob("*") if path.suffix in extensions and not any(part in ("target", "node_modules", "gen", ".git", "__pycache__") for part in path.relative_to(directory).parts) and (path.is_file() or path.is_symlink())]
    files = {}
    for path in sorted(paths):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 32 * 1024 * 1024:
            raise BundleError(f"Missing, linked, or oversized build input: {path}")
        files[path.relative_to(root).as_posix()] = path.read_bytes()
    for required in ("client/src/lib.rs", "client/src/main.rs", "client/examples/services.json", "client/examples/services.windows.json", "client/desktop/src-tauri/src/main.rs", "client/desktop/ui/index.html", "client/desktop/src-tauri/icons/icon.png", "client/desktop/src-tauri/icons/icon.ico"):
        if required not in files:
            raise BundleError(f"Missing build input: {required}")
    files["Build.cmd"] = windows_build_script()
    return files


def windows_build_script():
    lines = ["@echo off", "setlocal DisableDelayedExpansion", 'pushd "%~dp0" || exit /b 1',
             "where cargo >nul 2>nul", "if errorlevel 1 goto requirements", "where npm.cmd >nul 2>nul", "if errorlevel 1 goto requirements",
             'set "CARGO_BUILD_TARGET=x86_64-pc-windows-msvc"', 'set "CARGO_TARGET_DIR="', 'set "RUSTFLAGS=-C target-feature=+crt-static"',
             "cargo build --workspace --release --locked", "if errorlevel 1 goto failed",
             'call npm.cmd --prefix "client\\desktop" ci', "if errorlevel 1 goto failed",
             'call npm.cmd --prefix "client\\desktop" run build -- --target x86_64-pc-windows-msvc -- --locked', "if errorlevel 1 goto failed",
             'copy /y "target\\x86_64-pc-windows-msvc\\release\\sservcli.exe" "sservcli.exe" >nul', "if errorlevel 1 goto failed",
             'copy /y "client\\desktop\\src-tauri\\target\\x86_64-pc-windows-msvc\\release\\sservcli-desktop.exe" "sservcli-desktop.exe" >nul', "if errorlevel 1 goto failed",
             "echo Build complete. Run Start.cmd to connect all services.", "popd", "exit /b 0", ":requirements",
             "echo Install current stable Rust with the MSVC toolchain, Node.js, and Microsoft C++ Build Tools. WebView2 and OpenSSH Client are also required.",
             ":failed", "echo Build failed. See the compiler output above.", "popd", "exit /b 1"]
    return ("\r\n".join(lines) + "\r\n").encode()


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
    if not isinstance(config, dict) or not isinstance(config.get("ssh"), dict):
        raise BundleError("CONFIG must contain a client profile with an ssh object")
    ssh = config["ssh"]
    args.host, args.user = ssh.get("host"), ssh.get("user")
    if not args.host or args.host == "server.example.com":
        raise BundleError("Set ssh.host in CONFIG to the server's real reachable IP or hostname")
    if not isinstance(args.user, str):
        raise BundleError("Set ssh.user in CONFIG to a new forwarding-only account name")
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
    if not args.public_key or not args.public_key.is_file():
        raise BundleError("Set PUBKEY_FILE to the existing Windows client's Ed25519 PUBLIC key; private keys are never packaged")
    config = profile_for(args)
    if server.account(args.user) or os.path.lexists(f"/home/{args.user}"):
        raise BundleError("Account or home already exists; choose a new ssh.user in CONFIG or administer the existing managed account explicitly")
    output = (args.output or ROOT / f"dist/sservcli-windows-{args.user}-source.zip").absolute()
    if output.exists():
        raise BundleError(f"Output already exists; choose a new BUNDLE_OUTPUT: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    created = False
    with tempfile.TemporaryDirectory(prefix=".sservcli-bundle-", dir=output.parent) as scratch:
        directory = Path(scratch)
        inputs = read_binaries(args.windows_artifact) if args.windows_artifact else source_files()
        # Validate and gather build inputs before privileged account changes.
        policy_profile = directory / "server-policy.json"
        policy_profile.write_text(json.dumps(config), encoding="utf-8")
        if args.dry_run:
            print("Dry run: configuration, public key, and archive inputs validated; would generate missing host keys, start SSH, create account, register the client public key, and publish:", output)
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
            validate_profile(config)
            files = {**inputs, "services.json": (json.dumps(config, indent=2) + "\n").encode(),
                     "server-host-key.pub": (host_key + "\n").encode(),
                     "Start.cmd": b'@echo off\r\nsetlocal DisableDelayedExpansion\r\nif not exist "%~dp0sservcli-desktop.exe" (\r\n  echo Run Build.cmd first to create the Windows executables.\r\n  exit /b 1\r\n)\r\nstart "" "%~dp0sservcli-desktop.exe" --config "%~dp0services.json"\r\nendlocal\r\n',
                     "README.txt": ("sservcli Windows client\r\n\r\nExtract the entire ZIP into a folder under your Windows user account.\r\n"
                                    + ("Run Build.cmd in Windows Terminal, then run Start.cmd. Build.cmd needs current stable Rust (MSVC), Node.js, and Microsoft C++ Build Tools. Cargo/npm download their dependencies during this local build.\r\n" if not args.windows_artifact else "Native executables are included; run Start.cmd.\r\n") +
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
    step = "run Start.cmd" if args.windows_artifact else "run Build.cmd, then Start.cmd"
    print(f"Windows bundle ready: {output}\nDownload this ZIP to Windows, extract it, and {step}. No client private key was copied.")
    return output


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    env = os.environ
    default_config = Path(env.get("CONFIG") or "services.json")
    result.add_argument("--config", type=Path, default=default_config)
    result.add_argument("--public-key", type=Path, default=Path(env["PUBKEY_FILE"]) if env.get("PUBKEY_FILE") else None)
    result.add_argument("--host-key", type=Path, default=Path(env.get("HOST_KEY_FILE") or "/etc/ssh/ssh_host_ed25519_key.pub"))
    result.add_argument("--windows-artifact", type=Path, default=Path(env["WINDOWS_ARTIFACT"]) if env.get("WINDOWS_ARTIFACT") else None)
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
