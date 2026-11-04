#!/usr/bin/env python3
"""One-shot, network-free client packager; host SSH accounts are managed outside Docker."""
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import bundle_windows as bundle
from sservcli.config import validate_token
from sservcli.token_auth import write_private


def read_input(path, limit):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise bundle.BundleError(f"Invalid staged input: {path.name}")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise bundle.BundleError(f"Staged input is too large: {path.name}")
    return data


def package():
    owner = [os.environ.get(field, "") for field in ("BUNDLE_UID", "BUNDLE_GID")]
    if not all(value.isascii() and value.isdigit() and int(value) <= 2**31 - 1 for value in owner):
        raise bundle.BundleError("BUNDLE_UID and BUNDLE_GID must identify the host user")
    source = Path(os.environ.get("BUNDLE_INPUT") or "/input")
    output = Path(os.environ.get("BUNDLE_OUTPUT") or "/output/sservcli-windows-token.zip")
    config = json.loads(read_input(source / "services.json", 1024 * 1024).decode("utf-8"))
    bundle.validate_profile(config)
    if config["version"] != 2 or not config["ssh"].get("host_public_key"):
        raise bundle.BundleError("The host must provide a final token profile with its pinned SSH host key")
    token = validate_token(read_input(source / ".token", 64).decode("ascii").rstrip("\r\n"))
    with tempfile.TemporaryDirectory(prefix="sservcli-package-") as temporary:
        directory = Path(temporary)
        write_private(directory / "services.json", json.dumps(config))
        write_private(directory / ".token", token + "\n")
        args = bundle.parser().parse_args(["--client-only", "--config", str(directory / "services.json"),
                                          "--token-file", str(directory / ".token"), "--output", str(output)])
        # Force the packager to stay in client-only mode regardless of ambient
        # legacy/provisioning environment settings.
        args.client_only, args.legacy_ssh = True, False
        result = bundle.package(args)
    if result is not None:
        os.chown(result, int(owner[0]), int(owner[1]))
    return result


def main():
    try:
        package()
        return 0
    except (bundle.BundleError, OSError, ValueError) as error:
        print(f"sservcli-container-bundle: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
