"""Server-only entry point. The client is implemented in client/ (Go)."""
import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys
from .config import ConfigError, load_profile, token_profile


def main(argv=None):
    parser = argparse.ArgumentParser(description="Manage startup tokens on the existing OpenSSH server")
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("serve")
    command.add_argument("--config", type=Path, default=Path("var/services.windows.json"))
    command.add_argument("--state-dir", type=Path, default=Path(os.environ.get("SERVER_STATE") or "var/server"))
    command.add_argument("--port", type=int, default=int(os.environ["TOKEN_PORT"]) if os.environ.get("TOKEN_PORT") else None)
    command.add_argument("--sshd-config", default=os.environ.get("SSHD_CONFIG") or "/etc/ssh/sshd_config")
    command.add_argument("--ssh-service", default=os.environ.get("SSH_SERVICE") or "ssh")
    command.add_argument("--sshd-pid-file", default=os.environ.get("SSHD_PID_FILE") or None)
    command.add_argument("--host-key", default=os.environ.get("HOST_KEY_FILE") or "/etc/ssh/ssh_host_ed25519_key.pub")
    args = parser.parse_args(argv)
    try:
        return serve(args)
    except (ConfigError, OSError, ValueError, ImportError, subprocess.SubprocessError) as error:
        print(f"sservcli: {error}", file=sys.stderr)
        return 1


def serve(args):
    from .token_server import TokenServer
    config = token_profile(load_profile(args.config), args.port)
    server = TokenServer(config, args.state_dir, sshd_config=args.sshd_config,
                         ssh_service=args.ssh_service, host_key=args.host_key, sshd_pid_file=args.sshd_pid_file)
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
