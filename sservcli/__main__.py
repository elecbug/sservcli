"""Command-line entry point; GUI imports remain optional for headless servers."""
import argparse
import getpass
import json
import os
from pathlib import Path
import queue
import shlex
import signal
import subprocess
import sys
import tempfile

from .config import ConfigError, endpoint, load_profile, resolved_profile, save_profile, service_url, token_profile, validate_profile, validate_token
from .tunnel import Tunnel, launch_service, openssh_program, prepare_host_key, ssh_arguments


def parser():
    result = argparse.ArgumentParser(description="Multiple services through one verified SSH connection")
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("check", "list", "command", "connect", "desktop"):
        sub = commands.add_parser(name)
        sub.add_argument("--config", type=Path, default=None if name == "desktop" else Path("services.json"))
        if name == "connect":
            sub.add_argument("--open", dest="service")
            sub.add_argument("--token-file", type=Path, help="Read the 8-character token from a private file; otherwise use SSERVCLI_TOKEN or prompt")
        if name == "desktop":
            sub.add_argument("--background", action="store_true", help="Start in the Windows tray when a valid profile is available")
    sub = commands.add_parser("init", help="Create a profile using a supplied server public host key")
    for name in ("host", "user", "host-key"):
        sub.add_argument("--" + name, required=True)
    sub.add_argument("--identity")
    sub.add_argument("--fallback-hosts", default="", help="Comma-separated alternatives, in order")
    sub.add_argument("--port", type=int, default=22)
    sub.add_argument("--remote-port", type=int, default=8080)
    sub.add_argument("--local-port", type=int, default=18080)
    sub.add_argument("--config", type=Path, default=Path("services.json"))
    sub = commands.add_parser("serve", help="Issue a token password for a dedicated account on the existing OpenSSH server")
    sub.add_argument("--config", type=Path, default=Path("services.json"))
    sub.add_argument("--state-dir", type=Path, default=Path(os.environ.get("SERVER_STATE") or "var/server"))
    sub.add_argument("--port", type=int, default=int(os.environ["TOKEN_PORT"]) if os.environ.get("TOKEN_PORT") else None)
    sub.add_argument("--sshd-config", default=os.environ.get("SSHD_CONFIG") or "/etc/ssh/sshd_config")
    sub.add_argument("--ssh-service", default=os.environ.get("SSH_SERVICE") or "ssh")
    sub.add_argument("--host-key", default=os.environ.get("HOST_KEY_FILE") or "/etc/ssh/ssh_host_ed25519_key.pub")
    return result


def initialize(args):
    config = {"version": 1, "name": "My server", "ssh": {
        "host": args.host, "fallback_hosts": [host.strip() for host in args.fallback_hosts.split(",") if host.strip()],
        "port": args.port, "user": args.user, "identity_file": args.identity,
        "host_public_key": Path(args.host_key).read_text(encoding="utf-8").strip()},
        "reconnect": {"enabled": True, "max_attempts": 5, "initial_delay_secs": 2, "max_delay_secs": 30},
        "services": [{"id": "dashboard", "name": "Web service", "kind": "web", "remote_host": "127.0.0.1",
                      "remote_port": args.remote_port, "local_port": args.local_port, "enabled": True, "path": "/"}]}
    validate_profile(config)
    with tempfile.TemporaryDirectory(prefix="sservcli-host-") as directory:
        _, fingerprint = prepare_host_key(config["ssh"], directory)
    save_profile(args.config, config, exclusive=True)
    print(f"Created {args.config}\nPinned server host key: {fingerprint}\nUse connect --config to start the tunnel.")


def connect(config, service_id=None, token=None):
    selected = None
    if service_id:
        selected = next((s for s in config["services"] if s["id"] == service_id and s.get("enabled", True)), None)
        if selected is None:
            raise ConfigError(f"Unknown or disabled service: {service_id}")
    tunnel = Tunnel()
    stopping = False

    def stop(*_):
        nonlocal stopping
        stopping = True

    signals = (signal.SIGINT, signal.SIGTERM)
    if hasattr(signal, "SIGBREAK"):
        signals += (signal.SIGBREAK,)
    previous = {number: signal.signal(number, stop) for number in signals}
    try:
        tunnel.connect(config, token=token)
        opened = False
        while not stopping:
            try:
                status, message = tunnel.events.get(timeout=0.15)
            except queue.Empty:
                continue
            print(f"[{status}] {message}", file=sys.stderr, flush=True)
            if status == "failed":
                for line in tunnel.snapshot()["logs"]:
                    print("  " + line, file=sys.stderr)
                return 1
            if status == "connected" and selected and not opened:
                launch_service(selected)
                opened = True
        return 0
    finally:
        tunnel.disconnect()
        for number, handler in previous.items():
            signal.signal(number, handler)


def main(argv=None):
    if sys.version_info < (3, 11):
        print("sservcli requires Python 3.11 or newer", file=sys.stderr)
        return 1
    args = parser().parse_args(argv)
    try:
        if args.command == "serve":
            return serve(args)
        if args.command == "desktop":
            from .desktop import run
            return run(args.config, args.background)
        if args.command == "init":
            initialize(args)
            return 0
        config = load_profile(args.config)
        if args.command == "check":
            print(f"Valid profile: {config['name']} ({len(config['services'])} services)")
        elif args.command == "list":
            for service in config["services"]:
                address = service_url(service) if service["kind"] in ("web", "api") else endpoint(service)
                print(f"{service['id']:<16} {'enabled' if service.get('enabled', True) else 'disabled':<8} {address:<36} -> 127.0.0.1:{service['remote_port']}")
        else:
            config = resolved_profile(config, args.config)
            if args.command == "command":
                if config["version"] == 2:
                    raise ConfigError("Use connect for token profiles; it configures OpenSSH's private askpass helper")
                if config["ssh"].get("host_public_key"):
                    raise ConfigError("Use connect for host_public_key profiles; it creates and cleans up the pinned key file")
                argv = [openssh_program(), *ssh_arguments(config, config["ssh"]["known_hosts_file"])]
                print(subprocess.list2cmdline(argv) if os.name == "nt" else shlex.join(argv))
            else:
                token = None
                if config["version"] == 2:
                    if args.token_file:
                        from .token_auth import read_private
                        token = read_private(args.token_file).strip()
                    else:
                        token = os.environ.get("SSERVCLI_TOKEN")
                    if not token and sys.stdin.isatty():
                        token = getpass.getpass("Server token (8 characters, case-sensitive): ")
                    if not token:
                        raise ConfigError("Set SSERVCLI_TOKEN, use --token-file, or run interactively to enter the shared token")
                    validate_token(token)
                return connect(config, args.service, token)
        return 0
    except (ConfigError, OSError, ValueError, ImportError, subprocess.SubprocessError) as error:
        print(f"sservcli: {error}", file=sys.stderr)
        return 1


def serve(args):
    from .token_server import TokenServer
    config = token_profile(load_profile(args.config), args.port)
    server = TokenServer(config, args.state_dir, sshd_config=args.sshd_config,
                         ssh_service=args.ssh_service, host_key=args.host_key)
    stopping = False

    def stop(*_):
        nonlocal stopping
        stopping = True

    signals = [signal.SIGINT, signal.SIGTERM]
    if hasattr(signal, "SIGBREAK"):
        signals.append(signal.SIGBREAK)
    previous = {number: signal.signal(number, stop) for number in signals}
    try:
        server.start()
        if stopping:
            return 0
        print(f"OpenSSH token ready for {server.user}@{config['ssh']['host']}:{config['ssh'].get('port', 22)} (existing system sshd)", flush=True)
        if sys.stdout.isatty():
            print(f"Shared token: {server.token}", flush=True)
        else:
            print("New shared token written to the private token file (not emitted to redirected logs).", flush=True)
        print(f"Server public key: {server.public_key}", flush=True)
        print(f"Token file: {server.state_dir / 'access.token'}\nStop with Ctrl+C. Restarting issues a new token and closes existing connections.", flush=True)
        while not stopping:
            if server.process.poll() is not None:
                raise ConfigError("The OpenSSH token manager stopped; its token was revoked")
            server.stopping.wait(0.2)
        return 0
    finally:
        server.close()
        for number, handler in previous.items():
            signal.signal(number, handler)


if __name__ == "__main__":
    sys.exit(main())
