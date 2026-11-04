#!/usr/bin/env python3
"""Keep public Compose options intact when Docker is invoked through sudo."""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def literal(value):
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Compose options cannot contain control characters")
    return "'" + value.replace("'", "\\'") + "'"


def run(docker, command):
    options = {"CONFIG": str(Path(os.environ.get("CONFIG") or ROOT / "var/services.windows.json").absolute()),
               "BUILD_CLIENT": os.environ.get("BUILD_CLIENT") or "1",
               "WINDOWS_ARCH": os.environ.get("WINDOWS_ARCH") or "amd64",
               "NO_RESET_TOKEN": os.environ.get("NO_RESET_TOKEN") or "0",
               "SSERVCLI_BUNDLE_NAME": os.environ.get("SSERVCLI_BUNDLE_NAME") or "sservcli-windows-token.zip"}
    if options["NO_RESET_TOKEN"] not in ("0", "1"):
        raise ValueError("NO_RESET_TOKEN must be 0 or 1")
    executable = shlex.split(docker)
    if not executable:
        raise ValueError("DOCKER must specify the Docker command")
    # The file contains only public build/profile options, never credentials.
    # It is readable by sudo Docker without preserving the caller's environment.
    with tempfile.TemporaryDirectory(prefix="sservcli-compose-") as temporary:
        path = Path(temporary) / "options.env"
        path.write_text("".join(f"{key}={literal(value)}\n" for key, value in options.items()))
        path.chmod(0o600)
        environment = {key: value for key, value in os.environ.items() if key not in options}
        return subprocess.run([*executable, "compose", "--project-directory", str(ROOT),
                               "--file", str(ROOT / "docker-compose.yaml"), "--env-file", str(path),
                               *command], cwd=ROOT, env=environment).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", default=os.environ.get("DOCKER") or "docker")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        return run(args.docker, args.command[1:] if args.command[:1] == ["--"] else args.command)
    except (OSError, ValueError) as error:
        print(f"sservcli-compose: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
