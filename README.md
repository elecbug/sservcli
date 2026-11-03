# sservcli

Access several services on one server through one verified OpenSSH connection. The Windows desktop lists local service addresses, forwards every enabled service, and keeps running in the notification area.

The application is Python 3.11+ with the standard library and Tkinter. Transport uses the installed **OpenSSH `ssh` client and system `sshd` server**. There are no third-party Python packages or compilation steps.

## Quick start

On Ubuntu 24.04, install the server prerequisites:

```sh
sudo apt-get update
sudo apt-get install -y python3 openssh-server make
cp examples/services.token.windows.json services.json
```

Edit `ssh.host`, optional `ssh.fallback_hosts`, and the service ports in `services.json`. Set `ssh.port` to the port of your existing OpenSSH server, normally **22**. Then run:

```sh
make server CONFIG=services.json
```

The command requests sudo, prepares a restricted SSH account, and generates a case-sensitive **8-character token**. Keep it running. The token is that dedicated account's temporary SSH password. The command uses the existing system `sshd`; it does not open another SSH listening port or launch your web/DB/API programs.

The token appears on an interactive terminal and is also saved in a private file:

```sh
cat var/server/access.token
```

In another terminal on the same server, create the Windows download:

```sh
make bundle CONFIG=services.json
```

This prepares/reuses the same account, pins the **existing system SSH host public key**, and writes `dist/sservcli-windows-token.zip`. An existing ZIP is preserved; the next gets a suffix such as `-2.zip`. Bundling does not issue, rotate, or include a token. It can also run before `make server`; a newly prepared account remains locked until the server controller starts. **`PUBKEY_FILE` is unnecessary for token authentication.**

On Windows:

1. Install Python 3.11+ with Tcl/Tk and the Python launcher from [python.org](https://www.python.org/downloads/windows/).
2. Enable **OpenSSH Client** in Windows Optional Features.
3. Extract the entire ZIP into a folder under your Windows account.
4. Run **Build.cmd** to check prerequisites. No dependencies are downloaded or compiled.
5. Run **Start.cmd**, enter the token, and click **Connect**.

All enabled services forward together over one `ssh -L` process. Web/API services open in your default browser; other services display an endpoint or launch a configured local program. Closing the window keeps forwarding in the Windows tray. Tray **Quit** closes SSH and exits.

Only the SSH port needs to be reachable from the client. Keep the actual services on server loopback and retain their application-level authentication.

## Authentication and account lifecycle

- Tokens contain exactly eight characters from `A–Z`, `a–z`, and `0–9`, generated with Python's `secrets` module. Case matters.
- The client verifies the pinned system SSH host key before OpenSSH sends the token through encrypted password authentication. A missing or mismatched key prevents authentication.
- Each successful `make server` start issues a new token. Stopping the controller locks the dedicated password and closes that account's existing forwarding sessions. A controller crash closes its helper pipe, triggering the same revocation. A later start preserves the account and host identity while issuing another token.
- Root is needed to prepare the dedicated account, update its password, and apply its `sshd` policy. A small privileged helper stays alive while the controller runs so it can revoke access without another sudo prompt.
- An existing sservcli-managed account is verified and reused. A managed key-based account can migrate to token authentication; its UID and key files remain, but SSH public-key login is disabled for that account. An unrelated existing account is left intact and a dedicated name such as `svc_tunnel_token1` is selected automatically. The ZIP receives the selected username.
- Only configured `127.0.0.1:<remote_port>` destinations are allowed. Managed destinations from earlier runs are retained. Shells, command execution, SFTP, remote forwarding, agent/X11 forwarding, Unix-socket forwarding, and tunneling are disabled. `MaxSessions 0` permits forwarding while denying shell/subsystem sessions.
- Password authentication is enabled only in the dedicated account's managed `Match User` policy. Other accounts retain their administrator-configured authentication. Native OpenSSH authentication limits and the machine's PAM/password policy apply; `MaxAuthTries` is set to 3 for the dedicated account.
- Tokens never enter profile JSON, ZIPs, command arguments, or client logs. A private askpass helper supplies the token to OpenSSH through its child environment. The server prints the token only to an interactive terminal; redirected output refers to the private token file.
- **Remember on this device** stores a successfully authenticated token separately from the profile. Windows uses current-user DPAPI; Unix uses a private file. A rejected saved token is cleared. Unchecking the option forgets it.

The token grants the configured account's forwarding access; shared tokens do not provide individual user identities. Obtain the ZIP or pinned public key through a trusted administrator channel.

## Configuration

The supplied `examples/services.token.json` and `examples/services.token.windows.json` use version 2. A minimal profile is:

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

These addresses are documentation examples. Replace them with reachable addresses. `make bundle` adds `ssh.host_public_key` and the actual dedicated username to the client profile. The public key comes from `/etc/ssh/ssh_host_ed25519_key.pub` by default; its private counterpart stays with system `sshd`. `ssh-keygen -A` creates missing system host keys during preparation. A custom `HOST_KEY_FILE` must match a host key configured in the selected `sshd_config`.

Fallback IPs/hostnames are tried in array order after the primary fails. They must reach the same SSH identity and port. Up to 16 unique addresses are supported. Initial connection failure tries the address list once; authentication and host-key failures stop immediately. After an established connection drops, bounded reconnection starts with the next address. Restarting the server controller requires entering its new token.

Configure 1–64 services with unique IDs and local ports. Local ports must be 1024–65535; remote ports 1–65535. All local listeners and remote destinations use `127.0.0.1`. `enabled: false` controls client startup; the server policy includes every configured destination.

`kind` is `web`, `api`, `database`, or `tcp`. Web/API services support `scheme` (`http` or `https`) and `path`. An optional `launch` array supplies an executable and separate arguments, with `{host}`, `{port}`, and `{url}` placeholders. For example, the Windows example launches PostgreSQL through `wt.exe` and `psql.exe`. Import only profiles whose local launch commands you trust. SSH readiness confirms the forwarding transport; check the remote application separately if its endpoint fails.

## Commands and state

```sh
make setup
make server CONFIG=services.json
make bundle CONFIG=services.json
make bundle CONFIG=services.json DRY_RUN=1
make desktop CONFIG=/path/to/client-profile.json
make client-zip CONFIG=/path/to/existing/client-profile.json
```

`make client-zip` packages an existing final client profile, including its pinned host public key, without sudo or server changes. Both ZIP commands preserve earlier archives.

| Make input | Purpose |
| --- | --- |
| `CONFIG` | Services JSON; default `services.json`; an example file can be passed directly after editing its server address |
| `SERVER_STATE` | Private controller/token directory; default `var/server` |
| `SSHD_CONFIG` | System SSH configuration to manage; default `/etc/ssh/sshd_config` |
| `SSH_SERVICE` | OpenSSH systemd service; default `ssh` |
| `HOST_KEY_FILE` | Existing system SSH host public key; default `/etc/ssh/ssh_host_ed25519_key.pub` |
| `TOKEN_PORT` | Optional advertised SSH endpoint override; does not change the system daemon's listening port |
| `BUNDLE_OUTPUT` | Output ZIP path; a numeric suffix preserves existing archives |
| `DRY_RUN=1` | Validate bundle inputs and preview work without changing accounts or creating a ZIP |
| `PYTHON` / `VENV_DIR` | Python command / optional existing environment directory; defaults `python3` / `.venv` |

Run `server` and `bundle` with the same configuration and SSH settings. Managed account records live under `/var/lib/sservcli`. `SERVER_STATE` contains `access.token`, controller metadata, and a lock; it does not contain the system SSH private key. Private files/directories use 0600/0700 on Unix. Per-account and controller locks prevent simultaneous controllers from rotating each other's token.

Direct CLI commands need no environment setup beyond Python and OpenSSH:

```sh
python3 -m sservcli serve --config services.json --state-dir var/server
python3 -m sservcli check --config client-profile.json
python3 -m sservcli list --config client-profile.json
python3 -m sservcli connect --config client-profile.json
python3 -m sservcli connect --config client-profile.json --open dashboard
```

Interactive `connect` prompts without echo. Automation can use `--token-file /private/path/access.token` or `SSERVCLI_TOKEN`; tokens are not command-line arguments. Ctrl+C disconnects. `make server` runs in the foreground and does not install a startup service.

The desktop remembers its last profile and automatically forwards enabled services when it has a saved current token. Otherwise it shows the token input. Windows supports start-in-tray and one instance per user; a second launch opens the existing window. Linux/macOS minimize the window. The app does not install a login task.

Preferences, saved credentials, and startup logs live under `%LOCALAPPDATA%/sservcli` on Windows, or `$XDG_CONFIG_HOME/sservcli` / `~/.config/sservcli` on Unix. `Start.cmd` launches `pythonw.exe` to run without a console.

## Existing installations

Version 1 client profiles continue to support native OpenSSH private-key or Agent authentication. To retain that provisioning workflow explicitly:

```sh
make bundle LEGACY_SSH=1 PUBKEY_FILE=/path/to/client.pub CONFIG=legacy-services.json
```

This registers the client **public** key; the private key stays on the client. Existing managed accounts/keys are reused, additional keys are merged, and unrelated accounts are preserved. Token-managed accounts reject legacy key registration. Administrator `install`, `ensure`, `audit`, and `remove` commands remain in `server/sservcli_server.py`; `make render CONFIG=services.json` previews the account policy.

Profiles used with the earlier Python SSH server must be rebundled: use the existing system `sshd` port, its real host key, and the dedicated username. The old Python server's private key under `var/server` is no longer used. Stop an old server process separately before switching clients. A token rotation alone does not require a new ZIP; changes to the account name, host key, or service catalog do.

## Verification and troubleshooting

```sh
make check test
# Native SSH tests use temporary local sshd instances and services:
make integration
# Optional real Tk checks on Linux with Xvfb:
SSERVCLI_GUI_TESTS=1 xvfb-run -a python3 -m unittest discover -s tests -p test_desktop.py -v
```

The password integration tests additionally require `openssl` and `libnss-wrapper` (Ubuntu: `sudo apt-get install libnss-wrapper openssl`). They provide a private account database to the test daemon; no system users or passwords are changed. Tests cover native key/password authentication, token case/rotation/locking, pinned host keys, multiple forwards on one transport, failover/reconnection, channel restrictions, large payloads/half-close, bundle contents, provisioning rollback, and controller revocation. Windows-specific tests cover DPAPI, listener ownership, tray lifecycle, and child cleanup.

If a token is rejected, check its case and obtain the token from the currently running controller. System PAM password or lockout policies still apply. If the host key mismatches, verify the system SSH identity with the administrator before replacing the profile. If a local port is occupied, stop the older client or choose another local port.

If account preparation reports an earlier `Match`/`Include` conflict, inspect the effective policy with `sshd -T`; the installer audits its restrictions and rolls back policy changes on failure. If the machine's password policy rejects eight-character passwords, that policy must explicitly permit the requested token format before this authentication mode can be used.

For missing Tkinter, repair Python with Tcl/Tk enabled (`sudo apt-get install python3-tk` on an Ubuntu desktop). On Windows, `Build.cmd` checks Python, Tk, and native OpenSSH; no pip, Rust, Node.js, `gh`, or GitHub build is involved. Native Windows execution must still be verified on a Windows machine; this repository includes its platform-specific tests.
