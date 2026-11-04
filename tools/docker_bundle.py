#!/usr/bin/env python3
"""Prepare credentials on the SSH host, then build/package the client with Docker."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import bundle_windows as bundle
from sservcli.config import token_profile
from sservcli.token_auth import write_private


def package(args):
    if args.legacy_ssh or args.client_only:
        raise bundle.BundleError("Use make bundle LEGACY_SSH=1 or make client-zip for legacy/final-profile packaging")
    config = token_profile(bundle.load_profile(args.config), args.token_port)
    if config["ssh"]["host"] == "server.example.com":
        raise bundle.BundleError("Set ssh.host in CONFIG to the server's reachable IP or hostname")
    command = shlex.split(args.docker)
    if not command:
        raise bundle.BundleError("Set --docker to a Docker command, such as 'sudo docker'")
    compose = [*command, "compose", "--profile", "tools"]
    environment = {**os.environ, "WINDOWS_ARCH": args.arch, "BUILD_CLIENT": "0" if args.source_only else "1"}
    output = (args.output or ROOT / "dist/sservcli-windows-token.zip").absolute()
    if args.dry_run:
        bundle.runtime_files()
        print(f"Dry run: build the Docker client builder, verify the host's active token, and publish {output}.")
        print("The profile's existing SSH port and host key are used; the container opens no network listener.")
        return None
    # Fail on a missing credential before starting a potentially lengthy build.
    token = bundle.bundle_token(args, config)
    subprocess.run([*compose, "build", "builder"], cwd=ROOT, env=environment, check=True)
    (ROOT / "var").mkdir(exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".bundle-", dir=ROOT / "var") as scratch:
        directory = Path(scratch)
        # Refresh after the image build, then check against the host sshd's
        # current account lease. No SSH provisioning runs inside Docker.
        token = bundle.bundle_token(args, config)
        config = bundle.prepare_token_client(args, config, token, directory)
        # Only these two files are mounted in the builder; not server state,
        # host private keys, passwd/shadow, sshd configuration or Docker socket.
        (directory / "policy.json").unlink()
        write_private(directory / "services.json", json.dumps(config, indent=2) + "\n")
        write_private(directory / ".token", token + "\n")
        environment.update(SSERVCLI_BUNDLE_INPUT=str(directory), SSERVCLI_BUNDLE_OUTPUT=str(output.parent),
                           SSERVCLI_BUNDLE_UID=str(os.getuid()), SSERVCLI_BUNDLE_GID=str(os.getgid()),
                           SSERVCLI_BUNDLE_NAME=output.name)
        subprocess.run([*compose, "run", "--rm", "--no-deps", "builder"], cwd=ROOT, env=environment, check=True)
    print(f"Docker client bundle ready in {output.parent}; existing ZIPs receive numeric suffixes.")
    return output


def main(argv=None):
    parser = bundle.parser()
    parser.description = __doc__
    parser.set_defaults(config=Path(os.environ.get("CONFIG") or "var/services.windows.json"))
    parser.add_argument("--docker", default=os.environ.get("DOCKER") or "docker")
    args = parser.parse_args(argv)
    try:
        package(args)
        return 0
    except (bundle.BundleError, bundle.LegacySetupError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"sservcli-docker-bundle: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
