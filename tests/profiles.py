"""Version-one compatibility fixtures; public examples describe token mode."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def key_profile(windows=False):
    name = "services.token.windows.json" if windows else "services.token.json"
    profile = json.loads((ROOT / "examples" / name).read_text())
    profile["version"] = 1
    profile["ssh"].update(identity_file="~/.ssh/sservcli" if windows else "~/.ssh/id_ed25519", known_hosts_file="~/.ssh/known_hosts")
    profile["ssh"].pop("host_public_key", None)
    return profile
