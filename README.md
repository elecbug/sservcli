# sservcli

Forward several services through one verified **OpenSSH** connection. The client is entirely **Go**: it reads `services.json` and `.token` beside its executable, starts all enabled forwards, and runs in the background. Manage it from `http://127.0.0.1:8000` or the command line.

The server controller and account-provisioning tools remain Python 3.11+ standard-library programs. Transport still uses the existing system **`sshd`** and native **`ssh -L`**. Windows clients need OpenSSH Client, but neither Python nor Go is needed when the ZIP contains the compiled executables.

## Server in Docker Compose

On a Linux Docker host, the container uses host networking to access the existing services at `127.0.0.1:<remote_port>`. It runs its own OpenSSH daemon and token controller. The main profile is **`var/services.windows.json`**, mounted read-only. Its service addresses remain unchanged. The container defaults to SSH **2222**, and generated Windows profiles use that actual port instead of the native profile's SSH port.

```sh
make docker-up
make docker-status
make docker-bundle
```

If your account needs sudo to access Docker, use `make DOCKER="sudo docker" docker-up` and the same `DOCKER` setting for the other Docker targets. `docker-up` builds the image and waits for the server to become healthy; `docker-bundle` writes the minimal Windows download to `dist/sservcli-windows-token.zip`, including the current `.token`. The image builds both Windows EXEs once, so bundling inside the running container needs no Go compiler or systemd. When using the Make command, the ZIP belongs to the host user running Make and retains private permissions.

Copy `examples/server.docker.env` to **`var/docker.env`** to customize the listener (an existing file is preserved):

```dotenv
SSERVCLI_SSH_PORT=2222
SSERVCLI_LISTEN_ADDRESS=0.0.0.0
```

Choose an unused SSH port reachable by clients through the host firewall. `SSERVCLI_CONFIG=/path/to/profile.json make docker-up` selects a different profile. `WINDOWS_ARCH=arm64 make docker-up` builds ARM64 Windows clients; the default is AMD64. `make docker-bundle BUILD_CLIENT=0` retains the optional source-only download.

The private host key and controller state persist in **`var/docker-server/`**, separate from the native server's `var/server`. Docker state is root-owned; access the token and create downloads through the container. The account and managed SSH configuration stay inside the container and are provisioned again after container recreation. The host's accounts, SSH configuration, and existing SSH listener are not mounted or changed. Stopping the container revokes its token and forwarding sessions; restarting issues a new token while preserving its host key. Existing native-server clients need a new Docker-generated ZIP with the container's host key and port.

```sh
make docker-logs                    # Follow SSH/controller logs
docker compose restart server       # Issue a new token
make docker-bundle                  # Download with the new token
make docker-down                    # Stop the server; keep its state and downloads
```

The Compose service uses `network_mode: host`, without port mappings or a custom subnet. It shares the host network while keeping its filesystem and process namespace separate. [Docker host-network documentation](https://docs.docker.com/engine/network/drivers/host/)

## Server on the host and Windows download

On Ubuntu 24.04:

```sh
sudo apt-get update
sudo apt-get install -y python3 openssh-server make
cp examples/services.token.windows.json services.json
# Edit ssh.host, optional ssh.fallback_hosts, and service ports.
make server CONFIG=services.json
```

Keep this command running. It requests sudo, prepares/reuses a restricted account on the existing OpenSSH server, and issues a new case-sensitive **8-character token**. `ssh.port` must match your actual system SSH endpoint, normally **22**. The controller does not open another SSH port or start the underlying services.

In another terminal on that server:

```sh
make bundle CONFIG=services.json
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

After restarting `make server`, the old token stops working. Regenerate the ZIP with `make bundle`, or replace the client's `.token` with the new token and reconnect. The SSH host key does not change during token rotation.

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

The server token file is `SERVER_STATE/access.token`, default `var/server/access.token`; account records are under `/var/lib/sservcli`. Only the dedicated helper needs root and stays alive to revoke the token without another sudo prompt. The Python server has no third-party dependencies. Older Python client/desktop components have been removed.

## Build and package options

| Input | Purpose |
| --- | --- |
| `CONFIG` | Services JSON; default `services.json` |
| `SERVER_STATE` | Running controller's private state directory; default `var/server` |
| `BUILD_CLIENT=0` | Include sources and current token without compiling Windows executables |
| `WINDOWS_ARCH` | Windows binary architecture: `amd64` (default) or `arm64` |
| `BUNDLE_TOKEN_FILE` | Explicit private token source; normal bundle still verifies it against the active server |
| `BUNDLE_OUTPUT` | ZIP destination; existing downloads receive numeric suffixes |
| `DRY_RUN=1` | Preview bundling without compiling, provisioning, or creating a ZIP |
| `SSHD_CONFIG` / `SSH_SERVICE` | Existing SSH configuration/service; defaults `/etc/ssh/sshd_config` / `ssh` |
| `HOST_KEY_FILE` | Public key configured in system sshd; default `/etc/ssh/ssh_host_ed25519_key.pub` |
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

Go tests cover strict JSON/token handling, forwarding arguments, port conflicts, log redaction, launch arguments, and local API access controls. Native SSH integration tests exercise the Go executable with key/Agent/password authentication, multiple services on one connection, fallback/reconnection, token rotation/locking, host-key failures, channel restrictions, large payloads, half-close, and background/web management. Provisioning and bundle tests mock privileged system mutations. Windows AMD64/ARM64 cross-compilation is checked; direct native Windows execution still needs validation on a Windows machine.

For Linux, keep `.token` and private runtime files at mode 0600 and `.sservcli/` at 0700 (`chmod 600 .token` after extracting if needed). A missing or rejected token leaves management available so the file can be corrected and reloaded. Check `.sservcli/client.log` for failures. If a server policy audit reports an earlier `Match`/`Include` conflict, fix that SSH policy before retrying; the installer rolls back failed policy updates.
