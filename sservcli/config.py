"""Shared, strict profile validation and path handling (standard library only)."""
import copy
import json
import os
from pathlib import Path
import re
import tempfile


class ConfigError(ValueError):
    pass


def validate_profile(config):
    """Validate the shared profile schema for the client, server bundle, and GUI."""
    def fields(value, allowed, required, label):
        if not isinstance(value, dict) or set(value) - set(allowed) or set(required) - set(value):
            raise ConfigError(f"Invalid or unknown fields in {label}")
    def number(value, low, high, label):
        if type(value) is not int or not low <= value <= high:
            raise ConfigError(f"{label} must be an integer between {low} and {high}")
    def control(value):
        return any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value)
    def path(value):
        if not isinstance(value, str) or not value or control(value) or '"' in value or '%' in value:
            raise ConfigError("SSH paths must be nonempty and contain no controls, quotes, or % tokens")
    identifier = re.compile(r"[A-Za-z0-9_-]{1,64}")
    fields(config, ("version", "name", "ssh", "reconnect", "services"), ("version", "name", "ssh", "services"), "profile")
    if type(config["version"]) is not int or config["version"] not in (1, 2):
        raise ConfigError("Only profile versions 1 (SSH keys) and 2 (shared token) are supported")
    if not isinstance(config["name"], str) or not config["name"].strip() or len(config["name"].encode()) > 128:
        raise ConfigError("Profile name must contain 1-128 UTF-8 bytes")
    ssh = config["ssh"]
    token_mode = config["version"] == 2
    fields(ssh, ("host", "fallback_hosts", "port", "user", "host_public_key") if token_mode else
           ("host", "fallback_hosts", "port", "user", "identity_file", "known_hosts_file", "host_public_key"),
           ("host",) if token_mode else ("host", "user"), "ssh")
    fallback = ssh.get("fallback_hosts", [])
    if not isinstance(fallback, list):
        raise ConfigError("ssh.fallback_hosts must be an array")
    hosts = [ssh["host"], *fallback]
    if len(hosts) > 16 or any(not isinstance(host, str) or len(host) > 253 or host.startswith("-") or not re.fullmatch(r"[A-Za-z0-9.:-]+", host) for host in hosts):
        raise ConfigError("Configure at most 16 valid SSH hostnames/IPs")
    if len(set(host.lower() for host in hosts)) != len(hosts):
        raise ConfigError("SSH addresses must be unique")
    user = ssh.get("user", "svc_tunnel")
    if not isinstance(user, str) or not identifier.fullmatch(user) or user.startswith("-"):
        raise ConfigError("Invalid SSH username")
    number(ssh.get("port", 22), 1, 65535, "ssh.port")
    if ssh.get("identity_file") is not None:
        path(ssh["identity_file"])
    if not token_mode and (ssh.get("host_public_key") is None) == (ssh.get("known_hosts_file") is None):
        raise ConfigError("Set exactly one host-key verification source")
    if ssh.get("known_hosts_file") is not None:
        path(ssh["known_hosts_file"])
    if ssh.get("host_public_key") is not None:
        key = ssh["host_public_key"]
        if not isinstance(key, str) or len(key.strip().encode()) > 16384 or '\n' in key.strip() or '\r' in key.strip() or not re.fullmatch(r"(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521))\s+[A-Za-z0-9+/=]{16,}(?:\s+[^\r\n]*)?", key.strip()):
            raise ConfigError("Expected one plain server host public key")
    reconnect = config.get("reconnect", {})
    fields(reconnect, ("enabled", "max_attempts", "initial_delay_secs", "max_delay_secs"), (), "reconnect")
    if type(reconnect.get("enabled", True)) is not bool:
        raise ConfigError("reconnect.enabled must be a boolean")
    number(reconnect.get("max_attempts", 5), 0, 100, "reconnect.max_attempts")
    delay = reconnect.get("initial_delay_secs", 2)
    number(delay, 1, 300, "reconnect.initial_delay_secs")
    number(reconnect.get("max_delay_secs", 30), delay, 300, "reconnect.max_delay_secs")
    services = config["services"]
    if not isinstance(services, list) or not 1 <= len(services) <= 64:
        raise ConfigError("Configure 1-64 services")
    ids, ports = set(), set()
    for service in services:
        fields(service, ("id", "name", "kind", "remote_host", "remote_port", "local_port", "enabled", "path", "scheme", "launch"), ("id", "name", "kind", "remote_host", "remote_port", "local_port"), "service")
        if not isinstance(service["id"], str) or not identifier.fullmatch(service["id"]) or service["id"] in ids or not isinstance(service["name"], str) or not service["name"].strip():
            raise ConfigError("Services need unique ids and nonempty names")
        ids.add(service["id"])
        if service["kind"] not in ("web", "api", "database", "tcp") or service["remote_host"] != "127.0.0.1":
            raise ConfigError("Invalid service kind or remote_host")
        number(service["remote_port"], 1, 65535, "remote_port")
        number(service["local_port"], 1024, 65535, "local_port")
        if service["local_port"] in ports or type(service.get("enabled", True)) is not bool:
            raise ConfigError("Local ports must be unique and enabled must be a boolean")
        ports.add(service["local_port"])
        url_path = service.get("path", "/")
        if not isinstance(url_path, str) or not url_path.startswith("/") or url_path.startswith("//") or control(url_path) or any(c.isspace() or c == '\\' for c in url_path) or service.get("scheme", "http") not in ("http", "https"):
            raise ConfigError("Invalid service URL path or scheme")
        launch = service.get("launch")
        if launch is not None:
            if not isinstance(launch, list) or not launch or any(not isinstance(arg, str) or '\0' in arg for arg in launch) or not launch[0] or launch[0].startswith("-") or any(c in launch[0] for c in "{}"):
                raise ConfigError("Invalid launch executable/argument array")
            for arg in launch[1:]:
                rest = arg.replace("{host}", "").replace("{port}", "").replace("{url}", "")
                if '{' in rest or '}' in rest:
                    raise ConfigError("Unknown launch placeholder")


def resolve_path(value, directory):
    path = Path(value).expanduser()
    return str(path if path.is_absolute() else (Path(directory) / path).resolve())


def load_profile(path):
    path = Path(path).expanduser().resolve()
    if path.stat().st_size > 1024 * 1024:
        raise ConfigError("Profile must be smaller than 1 MiB")
    config = json.loads(path.read_text(encoding="utf-8-sig"))
    validate_profile(config)
    return config


def resolved_profile(config, path):
    validate_profile(config)
    result = copy.deepcopy(config)
    for name in ("identity_file", "known_hosts_file"):
        if result["ssh"].get(name):
            result["ssh"][name] = resolve_path(result["ssh"][name], Path(path).resolve().parent)
    return result


def save_profile(path, config, *, exclusive=False):
    validate_profile(config)
    path = Path(path).expanduser().resolve()
    text = json.dumps(config, indent=2, ensure_ascii=False) + "\n"
    if exclusive:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(text)
        return
    descriptor, temporary = tempfile.mkstemp(prefix=".sservcli-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def endpoint(service):
    return f"127.0.0.1:{service['local_port']}"


def service_url(service):
    return f"{service.get('scheme', 'http')}://{endpoint(service)}{service.get('path', '/')}"


def launch_arguments(service):
    if not service.get("launch"):
        return None
    replacements = {"host": "127.0.0.1", "port": str(service["local_port"]), "url": service_url(service)}
    return [arg.format_map(replacements) for arg in service["launch"]]


def token_profile(config, port=None):
    """Select token authentication while retaining the existing OpenSSH endpoint."""
    validate_profile(config)
    result = copy.deepcopy(config)
    ssh = config["ssh"]
    result["ssh"] = {"host": ssh["host"], "fallback_hosts": ssh.get("fallback_hosts", []),
                     "port": port if port is not None else ssh.get("port", 22), "user": ssh.get("user", "svc_tunnel")}
    if ssh.get("host_public_key"):
        result["ssh"]["host_public_key"] = ssh["host_public_key"]
    result["version"] = 2
    validate_profile(result)
    return result


def validate_token(token):
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9]{8}", token):
        raise ConfigError("Enter the case-sensitive 8-character token (A-Z, a-z, 0-9)")
    return token
