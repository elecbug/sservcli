# sservcli

Forward several services through one verified **OpenSSH** connection. The client is entirely **Go**: it reads `services.json` and `.token` beside its executable, starts all enabled forwards, and runs in the background. Manage it from `http://127.0.0.1:8000` or the command line.

The server controller and account-provisioning tools remain Python 3.11+ standard-library programs. Transport still uses the existing system **`sshd`** and native **`ssh -L`**. Windows clients need OpenSSH Client, but neither Python nor Go is needed when the ZIP contains the compiled executables.

## Docker server with the existing host SSH

The **server application runs persistently in Docker**, controlling the token lifecycle and creating Windows downloads. Connections use the **host's existing sshd, port, and host key**. For example, `ssh.port: 21200` continues to use port 21200. Forwarded services remain reachable at the host's `127.0.0.1` because the host sshd opens their connections.

Use a Linux host with systemd, Python 3.11+, OpenSSH Server, Make, and rootful Docker with Compose. The main configuration is **`var/services.windows.json`**. Set its public/fallback addresses and service ports; keep `ssh.port` equal to the existing SSH endpoint. Go is supplied by the Docker build image.

```sh
make DOCKER="sudo docker" docker-up
make DOCKER="sudo docker" docker-bundle
```

`docker-up` builds the image and Windows executables, installs/updates a small root-owned host helper, and starts the Docker server in the background. It waits for the server to obtain a working token lease. No separate `make server` process is needed. If your account has Docker access, omit `DOCKER="sudo docker"`; installing the host helper still requires sudo.

`docker-bundle` asks the running container to verify its current token against the host account and write **`dist/sservcli-windows-token.zip`**. The minimal download contains the two Windows EXEs, `services.json` with the existing host's public key and actual forwarding username, the current `.token`, start/stop scripts, a short guide, and checksums. Existing downloads receive numeric suffixes. The new ZIP belongs to the invoking host user and has mode 0600.

```sh
make DOCKER="sudo docker" docker-status
make DOCKER="sudo docker" docker-logs
make DOCKER="sudo docker" docker-down
```

Stopping the container revokes its token and closes that dedicated account's forwarding sessions. An abrupt container exit also revokes access through Unix-socket EOF; a paused/unresponsive controller loses its lease after 60 seconds without a heartbeat. Starting or restarting the server issues a fresh token, so create another download with `docker-bundle`. `docker-up` recreates the server to apply configuration and helper updates; it also rotates the token. Host SSH and other SSH accounts continue operating.

The container communicates with **`sservcli-ssh-bridge.service`** through a private Unix socket. This host helper handles the account/password and SSH policy operations that must affect the host. At installation, it saves an approved account/port list and copies its code into root-owned storage at `/var/lib/sservcli/ssh-bridge`. Requests cannot supply arbitrary commands, files, users, or destination ports. Updating those settings requires rerunning `docker-up` with sudo authorization. The helper starts automatically on host reboot and cleans up stale token access on startup/shutdown. Inspect its errors with:

```sh
sudo journalctl -u sservcli-ssh-bridge.service -n 100
```

Compose runs a single server with a read-only root filesystem and `network_mode: none`: all TCP traffic belongs to the existing host sshd. It mounts the public profile and helper socket directory read-only, plus `var/container-server` for private token state and `dist` for downloads. No host private keys, SSH configuration, account database, or Docker socket are mounted. There is no additional SSH listener, port mapping, or subnet to configure. `var/container-server` is root-owned container state; native host mode uses the separate `var/server` directory.

For migration, first stop any foreground `make server` process that owns the same account; its account lock intentionally prevents a second controller. Old `var/docker.env` and standalone-container state are unused. Removing old project containers with `docker-down` leaves host SSH running.

`WINDOWS_ARCH=arm64` selects ARM64 executables; AMD64 is the default. For an explicit source-only download, start the image with `docker-up BUILD_CLIENT=0` and run `docker-bundle BUILD_CLIENT=0`. `docker-build` builds the image without installing the helper or starting the server. A custom `CONFIG` must also be supplied to `docker-bundle` so Compose resolves the same profile.

## Optional native host server and Windows download

On Ubuntu 24.04:

```sh
sudo apt-get update
sudo apt-get install -y python3 openssh-server make
mkdir -p var
cp examples/services.token.windows.json var/services.windows.json
# Edit ssh.host, ssh.port, optional ssh.fallback_hosts, and service ports.
make server
```

Keep this command running. It requests sudo, prepares/reuses a restricted account on the existing OpenSSH server, and issues a new case-sensitive **8-character token**. `ssh.port` must match your actual system SSH endpoint, normally **22**. The controller does not open another SSH port or start the underlying services.

In another terminal on that server:

```sh
make bundle
```

With Go installed from [go.dev](https://go.dev/dl/), this cross-compiles the Windows client without CGO and creates `dist/sservcli-windows-token.zip`. The ZIP includes:

```text
sservcli.exe
sservcli-askpass.exe
services.json
.token
Start.cmd
Stop.cmd
README.txt
SHA256SUMS.txt
```

The default bundle contains only the executables, connection files, start/stop scripts, a short usage guide, and checksums. Go sources, example profiles, `Build.cmd`, and repository documentation are omitted. The server public key is already pinned in `services.json`, so no separate public-key file is needed.

**The current running server token is included in `.token`.** Bundling verifies it against the active dedicated account, without rotating it. Start `make server` first and run both commands as the same OS user with the same `CONFIG`, `SERVER_STATE`, and SSH settings. Missing, stale, or inactive tokens prevent publication. The host public key and actual selected SSH username are also included; private SSH keys stay on their original machines. Keep the downloaded ZIP private, since it contains a working credential.

To package Go sources and the current token without compiling on the server:

```sh
make bundle CONFIG=services.json BUILD_CLIENT=0
```

This explicit source-only option includes the Go sources, `Build.cmd`, and supporting documentation. On Windows, install Go and run `Build.cmd` once for that ZIP. This builds both Go executables; it does not use Python, pip, Rust, Node.js, or `gh`. `WINDOWS_ARCH=arm64` selects ARM64 for server-side compilation; the default is `amd64`. Existing ZIPs are preserved with suffixes such as `-2.zip`.

## Run the client

1. Enable **OpenSSH Client** in Windows Optional Features.
2. Extract the **entire** ZIP into a folder under your Windows account.
3. Run **Start.cmd**. It starts forwarding in the background and opens the local management page.

The client reads files beside `sservcli.exe`, regardless of the current working directory. `.token` contains exactly eight ASCII letters/digits, optionally followed by a newline. No environment file or interactive token entry is needed. `sservcli-askpass.exe` is the Go authentication helper; keep it beside the main EXE.

The local page shows connection status, the pinned host-key fingerprint, service addresses, and logs. It can connect/disconnect, open a configured service, and edit `services.json`. Save edits and reconnect to apply them. Adding server destinations also requires running server provisioning with the updated profile. Closing the browser leaves forwarding active. **Stop.cmd** or the page's stop button disconnects and exits.

The page binds only to `127.0.0.1:8000`. `Start.cmd` authorizes the browser through a private local session URL. Afterward, revisit `http://127.0.0.1:8000`; if a browser needs authorization again, run `sservcli.exe ui`. This local management credential is separate from the SSH token. The API checks the local host, origin, and session key, and never returns the contents of `.token`.

Useful commands:

```powershell
.\sservcli.exe start             # Background client; repeated start reuses it
.\sservcli.exe ui                # Open/authorize the management page
.\sservcli.exe status
.\sservcli.exe list              # Enabled/disabled services and local endpoints
.\sservcli.exe list --json
.\sservcli.exe reconnect         # Reread services.json and .token
.\sservcli.exe disconnect        # Keep management running, close SSH
.\sservcli.exe stop              # Stop management and all forwards
.\sservcli.exe run               # Foreground client with local management
.\sservcli.exe connect           # Foreground SSH only; Ctrl+C disconnects
.\sservcli.exe open --service dashboard
```

Launching the EXE without arguments starts the background client and opens management. It does not install a login task or system service. Runtime metadata, a process lock, and logs live in `.sservcli/` beside the executable; neither the control metadata nor logs contain the shared SSH token. Keep port 8000 available for management, or pass `--web-port` to `start`/`run`. SSH readiness does not prove that each remote application is healthy.

After restarting the server, the old token stops working. Regenerate the ZIP with `make docker-bundle` (Docker) or `make bundle` (native host), or replace the client's `.token` with the new token and reconnect. The SSH host key does not change during token rotation.

## Service configuration

Use `examples/services.token.json` or `examples/services.token.windows.json`. A minimal version 2 profile is:

```json
{
  "version": 2,
  "name": "My server",
  "ssh": {
    "host": "203.0.113.10",
    "fallback_hosts": ["198.51.100.20", "server.example.net"],
    "port": 22,
    "user": "svc_tunnel"
  },
  "reconnect": {
    "enabled": true,
    "max_attempts": 5,
    "initial_delay_secs": 2,
    "max_delay_secs": 30
  },
  "services": [
    {
      "id": "dashboard",
      "name": "Web dashboard",
      "kind": "web",
      "remote_host": "127.0.0.1",
      "remote_port": 8080,
      "local_port": 18080,
      "enabled": true,
      "path": "/"
    }
  ]
}
```

Replace the documentation addresses. `make bundle` adds `ssh.host_public_key` from the system OpenSSH host key, normally `/etc/ssh/ssh_host_ed25519_key.pub`, and fills the actual dedicated username. The client refuses token authentication without a pinned key and stops on a key mismatch. The private host key is never packaged.

Fallback addresses are tried in order and must reach the same host identity and SSH port. Up to 16 unique addresses are supported. Authentication/key failures stop immediately. After a previously established transport drops, bounded reconnection starts with the next address.

Configure 1–64 services with unique IDs and local ports. Local ports are 1024–65535 and remote ports 1–65535; all listeners/destinations use `127.0.0.1`. `enabled: false` skips a client forward; the server allowlist includes all configured services. A single `ssh` process handles every enabled `-L` forwarding rule.

`kind` is `web`, `api`, `database`, or `tcp`. Web/API entries support `scheme` (`http`/`https`) and `path`. Optional `launch` arrays specify a local executable plus separate arguments, expanding `{host}`, `{port}`, and `{url}` without a shell. Command-line DB tools can launch through a terminal, as in the Windows example. Import only profiles whose local launch commands you trust. Applications retain their own authentication; only the SSH port needs to be publicly reachable.

## Server token and account lifecycle

Tokens use Python's `secrets` module and exactly eight characters from `A–Z`, `a–z`, and `0–9`. Each successful controller start issues a fresh token as the dedicated account's SSH password. Native OpenSSH verifies the pinned server key before sending the password through encrypted authentication. Tokens are provided to OpenSSH through a private child environment, never command arguments or logs.

Stopping the server controller locks its password and closes that account's existing forwarding sessions. Controller pipe EOF also triggers revocation after a controller crash. Account and controller locks prevent concurrent token rotation. Native OpenSSH/PAM authentication and password policies remain effective, including `MaxAuthTries 3`; the system password policy must permit the requested eight-character format.

Managed accounts are verified and reused. Existing unrelated users are preserved; a dedicated name such as `svc_tunnel_token1` is chosen instead. Migrating a managed key account preserves its UID/key files but disables public-key login for that token account. Retained managed destinations remain allowed. Its policy permits only local forwarding to configured loopback destinations, with `MaxSessions 0` and no shell, commands, SFTP, remote forwarding, agent/X11 forwarding, Unix-socket forwarding, or tunneling. Other accounts keep their existing authentication policy.

The native server token file is `SERVER_STATE/access.token`, default `var/server/access.token`. Docker uses `/state/access.token` inside the container, backed by root-owned `var/container-server/access.token` on the host. Account records are under `/var/lib/sservcli`. Host privilege helpers stay alive to revoke the token without another sudo prompt. The Python server has no third-party dependencies. Older Python client/desktop components have been removed.

## Build and package options

| Input | Purpose |
| --- | --- |
| `CONFIG` | Services JSON; default `var/services.windows.json` |
| `SERVER_STATE` | Running controller's private state directory; default `var/server` |
| `BUILD_CLIENT=0` | Include sources and current token without compiling Windows executables |
| `WINDOWS_ARCH` | Windows binary architecture: `amd64` (default) or `arm64` |
| `BUNDLE_TOKEN_FILE` | Explicit private token source; normal bundle still verifies it against the active server |
| `BUNDLE_OUTPUT` | ZIP destination; existing downloads receive numeric suffixes |
| `DRY_RUN=1` | Preview bundling without compiling, provisioning, or creating a ZIP |
| `SSHD_CONFIG` / `SSH_SERVICE` | Existing SSH configuration/service; defaults `/etc/ssh/sshd_config` / `ssh` |
| `HOST_KEY_FILE` | Public key configured in system sshd; default `/etc/ssh/ssh_host_ed25519_key.pub` |
| `SSERVCLI_BUNDLE_NAME` | Docker ZIP filename within `dist`; default `sservcli-windows-token.zip` |
| `TOKEN_PORT` | Advertised SSH endpoint override; does not change the daemon's listening port |

`make client-zip CONFIG=/path/to/final/services.json` repackages a final profile without server/account changes, using its adjacent `.token` or `BUNDLE_TOKEN_FILE`. It includes that supplied token without claiming to verify a live remote server. Use a profile whose public host key is already pinned. Version 1 key/Agent profiles remain supported; `make bundle LEGACY_SSH=1 PUBKEY_FILE=/path/client.pub CONFIG=legacy.json` retains the explicit public-key provisioning workflow and needs no `.token`.

For development, use Go 1.22+ (a current Go release is recommended):

```sh
make build                 # Native client: client/sservcli
make build-windows         # dist/sservcli.exe and its Go askpass helper
make check test
# Optional isolated sshd/password tests (no system account changes):
sudo apt-get install libnss-wrapper openssl
make integration
```

Go tests cover strict JSON/token handling, forwarding arguments, port conflicts, log redaction, launch arguments, and local API access controls. Native SSH integration tests exercise the Go executable with key/Agent/password authentication, multiple services on one connection, fallback/reconnection, token rotation/locking, host-key failures, channel restrictions, large payloads, half-close, and background/web management. Provisioning tests mock privileged system mutations. Docker controller tests use real Unix sockets and child processes with a fake account helper to verify token revocation, approved scopes, and minimal downloads without changing host accounts. Windows AMD64/ARM64 cross-compilation is checked; direct native Windows execution still needs validation on a Windows machine.

For Linux, keep `.token` and private runtime files at mode 0600 and `.sservcli/` at 0700 (`chmod 600 .token` after extracting if needed). A missing or rejected token leaves management available so the file can be corrected and reloaded. Check `.sservcli/client.log` for failures. If a server policy audit reports an earlier `Match`/`Include` conflict, fix that SSH policy before retrying; the installer rolls back failed policy updates.
