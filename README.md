# sservcli

Access several services on one server through one encrypted SSH connection. Start the Python server, share its **8-character startup token**, and enter that token in the Windows client. All enabled services forward automatically; the desktop lists their local addresses and runs in the Windows notification area.

The application uses Python 3.11+, Tkinter, and [Paramiko](https://www.paramiko.org/). Both the token server and client are Python programs. Token mode needs no OS account creation, client private keys, SSH Agent, system `sshd`, Rust, Node.js, or native compilation. The older OpenSSH public-key workflow remains available explicitly.

## Quick start

On the server, install Python 3.11+, its venv support, and Make. For Ubuntu 24.04:

```sh
sudo apt-get update
sudo apt-get install -y python3 python3-venv make
```

Copy an example and edit the reachable server address, optional fallback addresses, and service ports:

```sh
cp examples/services.token.windows.json services.json
# Edit ssh.host, ssh.fallback_hosts, and services.
make server CONFIG=services.json
```

`make server` installs the pinned Python dependencies into `.venv` on first use, creates/preserves the server's host identity under `var/server`, and listens on port **8022**. It displays a new token on an interactive terminal. The token is also written to the private file:

```sh
cat var/server/access.token
```

Keep that server process running. In another terminal, create the Windows ZIP:

```sh
make bundle CONFIG=services.json
```

The output is `dist/sservcli-windows-token.zip`. Existing archives receive numeric suffixes such as `-2.zip`; earlier downloads are preserved. Packaging prepares the same persistent server host identity if needed, so it can also run before the server. Packaging does **not** issue a token or include one in the ZIP. `PUBKEY_FILE` is not needed in token mode.

On Windows:

1. Install Python 3.11+ with Tcl/Tk and the Python launcher from [python.org](https://www.python.org/downloads/windows/).
2. Extract the entire ZIP into a folder under your Windows account.
3. Run **Build.cmd** once to create `.venv` and install the pinned SSH dependencies. Internet access is needed for this first installation. Only binary wheels are accepted; no compiler is invoked.
4. Run **Start.cmd**, enter the token shown by the server, and click **Connect**.

The client authenticates once and forwards all enabled services. Click the tray icon to view services or copy an endpoint. Closing the window keeps forwarding; tray **Quit** disconnects and exits. The server's configured port must be reachable through your firewall. Your actual web/DB/API services should listen on server loopback and retain their own authentication.

## Token behavior

- Every token is exactly **8 characters**, chosen with Python's `secrets` module from `A–Z`, `a–z`, and `0–9`: 62 possible characters per position.
- Authentication is case-sensitive. The token is sent only inside an encrypted SSH connection, after the client verifies the pinned server public key included in the ZIP.
- Each successful server start generates a fresh token. Stopping/restarting the server closes existing connections and invalidates the previous token. Share the new token with clients after a restart; the persistent server key means they do not need a new ZIP for token rotation alone.
- Five failed attempts from one source IP within 60 seconds temporarily block that source. A global limit of 50 failures within 60 seconds also applies. After repeated mistakes, wait 60 seconds before trying again. Clients sharing a public IP share its limit.
- Shell, command execution, SFTP, remote forwarding, agent/X11 forwarding, and unknown channel types are denied. Only configured `127.0.0.1:<remote_port>` destinations are allowed. A shared token grants access to that server's configured destinations; it is not a per-user permission system.
- Tokens are excluded from ZIPs and profile JSON. Client diagnostic logs never print them. The server prints its token only to an interactive terminal; when stdout is redirected, read the private token file instead of searching logs.
- **Remember on this device** saves a successfully authenticated token separately from the profile. Windows uses current-user [DPAPI protection](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata); Unix stores it in a private directory/file. Unchecking the option forgets the saved token. A rejected saved token is cleared so the new startup token can be entered.

The server uses SSH's encrypted password-authentication exchange for this application token. It does not enable password login in the machine's OpenSSH configuration or modify any OS user.

## Configuration

The token server/client uses profile version 2:

```json
{
  "version": 2,
  "name": "My server",
  "ssh": {
    "host": "203.0.113.10",
    "fallback_hosts": ["198.51.100.20", "server.example.net"],
    "port": 8022
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
    },
    {
      "id": "postgres",
      "name": "PostgreSQL",
      "kind": "database",
      "remote_host": "127.0.0.1",
      "remote_port": 5432,
      "local_port": 15432,
      "enabled": true,
      "launch": ["wt.exe", "new-tab", "--", "psql.exe", "-h", "{host}", "-p", "{port}", "-U", "app", "app"]
    }
  ]
}
```

The addresses above are documentation examples. Use your actual reachable address. `make bundle` adds `ssh.host_public_key` from the server's persistent identity to the client's profile. A client refuses to send its token without a pinned key, and it stops immediately on a mismatch. Obtain bundles/public keys through a trusted administrator channel.

Alternative IPs/hostnames are tried in array order after the primary fails. They must reach the same server identity and port. Up to 16 unique addresses are supported. After an established transport drops, bounded reconnection starts with the next address. Initial connection failure tries the address list once; authentication and host-key failures stop immediately. Automatic reconnection uses the current token, so a server restart requires entering its new token.

Configure 1–64 services with unique IDs and local ports. Local ports must be 1024–65535; remote ports 1–65535. Every local listener and remote destination uses `127.0.0.1`. `enabled: false` is a client preference; the server allowlist includes all configured service destinations.

`kind` is `web`, `api`, `database`, or `tcp`. Web/API services open in the default browser; `scheme` defaults to `http` and may be `https`, while `path` defaults to `/`. An optional `launch` array names an executable and separate arguments, with `{host}`, `{port}`, and `{url}` placeholders. Command-line DB tools should be launched through a terminal, as in the Windows example. Launch arrays execute local programs, so import only profiles you trust. A ready listener indicates SSH forwarding is available; remote application health and service-level authentication remain separate.

## Commands and state

```sh
make setup
make server CONFIG=services.json
make bundle CONFIG=services.json
make desktop CONFIG=/path/to/client-profile.json
make client-zip CONFIG=/path/to/existing/client-profile.json
```

`make client-zip` repackages an existing client profile without changing the server identity or provisioning anything. Use the generated client's profile, including its pinned public key. Both ZIP commands preserve earlier archives by adding numeric suffixes.

| Make input | Purpose |
| --- | --- |
| `CONFIG` | Services JSON; default `services.json` |
| `SERVER_STATE` | Private server identity/token directory; default `var/server`; use the same value for `server` and `bundle` |
| `TOKEN_PORT` | Optional server/bundle port override; otherwise version 2 uses `ssh.port` or 8022 |
| `LISTEN` | Server listening IP; default `0.0.0.0`; use `127.0.0.1` for a local-only server |
| `BUNDLE_OUTPUT` | ZIP path; a numeric suffix is added if it exists |
| `DRY_RUN=1` | Preview bundle inputs without creating identity, token, accounts, or ZIP; dependency setup may still run |
| `PYTHON` / `VENV_DIR` | Bootstrap Python / Make's environment directory; defaults `python3` / `.venv` |

`SERVER_STATE/host_ed25519` is the private host key and must stay on the server. `host_ed25519.pub` is its public half. `access.token` contains only the current 8-character token. The directory and private files use modes 0700/0600 on Unix. Only one server process may use a state directory at a time; a duplicate launch cannot rotate the running server's token. Back up the host identity if clients should keep trusting the server after migration.

Run `server` and `bundle` as the same OS user. Token mode does not require sudo.

For direct CLI use after setup:

```sh
.venv/bin/python -m sservcli serve --config services.json --state-dir var/server
.venv/bin/python -m sservcli check --config client-profile.json
.venv/bin/python -m sservcli list --config client-profile.json
.venv/bin/python -m sservcli connect --config client-profile.json
.venv/bin/python -m sservcli connect --config client-profile.json --open dashboard
```

Interactive `connect` prompts for the token without echo. Automation may read it with `--token-file /private/path/access.token` or `SSERVCLI_TOKEN`; tokens are not accepted as command-line arguments. Ctrl+C disconnects. `make server` stays in the foreground until stopped; it does not install a system service or automatically launch the underlying web/DB/API programs.

The desktop remembers its last profile and starts all enabled forwards when it launches and has a saved current token. Without a saved token it shows the input field. Windows supports start-in-tray, show/connect/disconnect/quit, and one instance per user; a second launch shows the existing window. Linux/macOS minimize the window instead of using a native tray. Launching the app does not install a login task.

Preferences, remembered tokens, and startup logs are under `%LOCALAPPDATA%\sservcli` on Windows, or `$XDG_CONFIG_HOME/sservcli` / `~/.config/sservcli` on Unix. Profiles contain service metadata and public server identity, not the shared token. `Start.cmd` uses `pythonw.exe` from the local environment to run without a console.

## Existing SSH-key installations

`examples/services.json` and `examples/services.windows.json` remain version 1 examples. Existing version 1 client profiles still use OpenSSH with the configured private key or Agent. New `make server`/`make bundle` runs can accept those files as inputs and convert them to token mode: OS user/private-key/known-hosts settings are removed, the token SSH port defaults to 8022, and the bundle uses the Python server's own persistent public key. Use `TOKEN_PORT` to select a different port.

To keep the former OS-account/public-key provisioning workflow explicitly:

```sh
make bundle LEGACY_SSH=1 PUBKEY_FILE=/path/to/client.pub CONFIG=legacy-services.json
```

Legacy provisioning requires Ubuntu/OpenSSH and sudo. Missing dedicated accounts are created. Existing sservcli-managed accounts are verified/reused, missing public keys are added, matching key identities are not duplicated, and old keys/destinations are preserved. External existing accounts skip account/key/policy changes and rely on their administrator-managed SSH setup. Existing accounts are never deleted by bundle cleanup; cleanup targets only an account created by that invocation. Genuine policy/metadata errors still report an error.

The explicit administrator commands remain available:

```sh
make render CONFIG=legacy-services.json
sudo python3 server/sservcli_server.py install --config legacy-services.json --public-key /path/client.pub --ensure-ssh
sudo python3 server/sservcli_server.py audit --config legacy-services.json
sudo python3 server/sservcli_server.py remove --user svc_tunnel
```

`install` remains create-only; legacy bundling uses idempotent `ensure`. These commands manage the previous restricted `sshd` accounts and do not configure the new token server. Token mode does not remove or change previously provisioned accounts. See the [OpenSSH server manual](https://man.openbsd.org/sshd_config) for its separate policy controls.

## Verification and troubleshooting

```sh
make check test
make integration  # additionally requires local openssh-server for legacy tests
# Optional real Tk checks on Linux, with Xvfb installed:
SSERVCLI_GUI_TESTS=1 xvfb-run -a .venv/bin/python -m unittest discover -s tests -p test_desktop.py -v
```

Tests cover token alphabet/length/case, rate limits, rotation and expiry, persistent identity, checking identity before sending a token, one SSH transport for multiple services, half-close/large payloads, forbidden destinations/channels, failover/reconnect, local credential storage, bundle secret exclusion, and the previous key/account workflow. Real SSH tests use temporary state and local services; no production accounts are modified. Native Windows tests cover DPAPI, listener ownership, tray lifecycle, and child cleanup for legacy mode.

If a token is rejected, check its case, obtain the latest startup token, and wait 60 seconds after repeated failures. If the server key mismatches, verify the server identity with the administrator before replacing the client's profile; deleting the state directory creates a new identity. If a local port is occupied, stop the older client or change that service's local port. If SSH is ready but a service fails, check the corresponding application on server loopback.

For missing Tkinter, repair the Python installation with Tcl/Tk enabled (Ubuntu desktop: `sudo apt-get install python3-tk`). Run `Build.cmd` again if Python dependencies are missing on Windows. The installer accepts only binary wheels and reports an error instead of attempting a Rust/C build if compatible wheels are unavailable. No `gh` or GitHub build is used. Native Windows execution still needs verification on a Windows machine; the repository provides the corresponding tests.
