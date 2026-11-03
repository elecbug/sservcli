# sservcli

Use several services on one server through a single verified SSH connection. The client starts every enabled forward automatically and lists the local addresses in a desktop window. On Windows it runs in the notification area; closing the window keeps the forwards running.

The entire application uses **Python 3.11+ and its standard library**. The desktop uses Tkinter; Windows integration uses `ctypes`. There are no pip dependencies. OpenSSH supplies the transport. The Ubuntu server uses its existing `sshd`; no application daemon runs on the server.

## Requirements

| System | Requirements |
| --- | --- |
| Ubuntu server | Python 3.11+, OpenSSH server/client, GNU Make; sudo for account provisioning |
| Windows client | Windows 10/11, Python 3.11+ with Tcl/Tk and the Python launcher, Windows OpenSSH Client |
| Linux/macOS desktop | Python 3.11+, working Tkinter, OpenSSH Client, a graphical session |

Install Python on Windows from [python.org](https://www.python.org/downloads/windows/), with Tcl/Tk enabled. The embeddable distribution does not include Tkinter. Enable **OpenSSH Client** in Windows Optional Features. `python -m tkinter` verifies the GUI installation. See the [Tkinter documentation](https://docs.python.org/3/library/tkinter.html) and [Python on Windows](https://docs.python.org/3/using/windows.html).

On Ubuntu 24.04:

```sh
sudo apt-get update
sudo apt-get install -y python3 openssh-server make
```

For the Linux GUI, also install `python3-tk`. Server provisioning and ZIP generation do not import Tkinter.

## Prepare the server and Windows ZIP

Use your existing SSH private key or SSH Agent on Windows. If you need a new client key, generate it **on Windows**, for example in PowerShell:

```powershell
ssh-keygen -t ed25519 -f "$env:USERPROFILE/.ssh/sservcli"
```

Transfer only `sservcli.pub` to the server administrator. Keep the private `sservcli` file on Windows. `PUBKEY_FILE` is the **client login public key**, separate from the server host key.

On the server, copy the example and edit it:

```sh
cp client/examples/services.windows.json services.json
```

Set `ssh.host` to the reachable server IP/hostname, `ssh.user` to a **new** dedicated account, and `ssh.fallback_hosts` to an ordered array of alternative addresses. Adjust the service ports. Set `ssh.identity_file` to your existing private key's Windows path, such as `~/.ssh/sservcli`, or `null` for Agent/default identities. `CONFIG` describes the Windows client, so this path need not exist on the server.

Preview, then provision and package:

```sh
make bundle PUBKEY_FILE=/path/to/sservcli.pub CONFIG=services.json DRY_RUN=1
make bundle PUBKEY_FILE=/path/to/sservcli.pub CONFIG=services.json
```

The command validates the settings and Python files, generates missing server host keys, enables/starts SSH, creates the restricted account, registers the client public key, and produces:

```text
dist/sservcli-windows-<ssh.user>-python.zip
```

The packaged profile pins the actual server public host key. The ZIP contains the Python client, `Start.cmd`, `Build.cmd`, examples, documentation, and `SHA256SUMS.txt`. Private keys are never copied. Packaging is local and requires no GitHub, `gh`, Rust, Node.js, or Windows build host. Sudo is needed only for provisioning. Existing accounts, homes, and output ZIPs are refused. A packaging failure after successful account creation attempts to remove only that newly created managed account.

Download with your normal administrator account, extract the **entire ZIP** under your Windows user account, and double-click **Start.cmd**. The forwarding account cannot use SFTP/SCP. Every enabled service connects automatically. Click the tray icon to show the service list; use tray **Quit** to stop forwarding. `Build.cmd` checks prerequisites and does not compile anything.

| Optional input | Purpose |
| --- | --- |
| `BUNDLE_OUTPUT` | A new output ZIP path |
| `HOST_KEY_FILE` | Server host public key; default `/etc/ssh/ssh_host_ed25519_key.pub` |
| `SSHD_CONFIG` / `SSH_SERVICE` | SSH config/service; defaults `/etc/ssh/sshd_config` / `ssh` |
| `DRY_RUN=1` | Validate without changing accounts or publishing a ZIP |
| `PYTHON` | Make's Python executable; default `python3` |

`CONFIG` defaults to `services.json`. `PUBKEY_FILE` is required for `bundle` and must contain one plain Ed25519 public key.

## Updating an existing installation

Existing version 1 profiles work with the Python client. For an already provisioned account, use the final `services.json` from the previous ZIP, including its pinned `host_public_key`:

```sh
make client-zip CONFIG=/path/to/existing/services.json BUNDLE_OUTPUT=dist/sservcli-python-update.zip
```

This packages the client without server account changes or `PUBKEY_FILE`. Extract into a new folder and run `Start.cmd`. Keep your existing private key/Agent and stop the old client first to release its local ports.

The Rust/Tauri client has been replaced. Previously downloaded ZIPs still contain the old `Build.cmd`; extract the **new Python ZIP** to use the new implementation. Updating the server checkout does not update files already downloaded to Windows. The new script never invokes Cargo, so the former `edition2024` error no longer applies. Python must be installed on Windows: this ZIP does not bundle a Python runtime or standalone executable.

## Configuration

All local listeners and remote destinations use loopback:

```json
{
  "version": 1,
  "name": "My server",
  "ssh": {
    "host": "203.0.113.10",
    "fallback_hosts": ["198.51.100.20", "server.example.net"],
    "port": 22,
    "user": "svc_tunnel",
    "identity_file": "~/.ssh/sservcli",
    "host_public_key": "ssh-ed25519 REPLACE_WITH_THE_REAL_SERVER_HOST_PUBLIC_KEY"
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

Replace documentation addresses and the host-key placeholder before connecting.

- The primary address is tried first, then alternatives in order. At most 16 unique addresses are allowed. They must reach the **same host key**. Host verification/authentication failures stop the connection; fallbacks cannot bypass them.
- After an established connection drops, recovery starts with the next address. Reconnection uses bounded exponential delays and at most `max_attempts` recovery cycles across the session. Initial connection failure exhausts the address list once and stops.
- All enabled services share one SSH process. Set `enabled: false` to skip a service. At least one must be enabled to connect.
- Configure 1–64 services with unique IDs and local ports. Local ports must be 1024–65535 and remote ports 1–65535. `remote_host` must be `127.0.0.1`.
- `kind` is `web`, `api`, `database`, or `tcp`. Web/API services open in the default browser. `scheme` defaults to `http` and may be `https`; `path` defaults to `/`.
- `launch` is an executable/argument array supporting `{host}`, `{port}`, and `{url}`. It runs without a shell. GUI users should launch command-line tools through a terminal, as in the PostgreSQL example. Alternatively, copy the endpoint into an external client.
- Relative key/known-hosts paths resolve from the profile directory; `~` resolves to the client user's home. In JSON use `/` or doubled backslashes for Windows paths.
- Set exactly one of `host_public_key` or `known_hosts_file`. Pinned keys apply to all addresses. An existing known-hosts file must already trust each address under the selected SSH port. Unknown keys are never accepted automatically.
- `identity_file: null` uses Agent/default identities. An explicit key uses `IdentitiesOnly=yes`. For encrypted keys, load the key into SSH Agent beforehand; the background client never prompts for a passphrase.
- Profiles are trusted local files because `launch` can run a program. Import only profiles you trust. SSH uses `-F none`, strict host verification, public-key authentication, and no shell interpolation.

Services keep their own authentication and authorization. A ready listener confirms that SSH forwarding is available; it does not prove the remote application is healthy.

## Desktop and CLI

Run from the repository or extracted ZIP:

```sh
python -m sservcli desktop --config services.json
python -m sservcli check --config services.json
python -m sservcli list --config services.json
python -m sservcli connect --config services.json
python -m sservcli connect --config services.json --open dashboard
```

Use `python3` where appropriate, or `py -3` on Windows. Ctrl+C stops the foreground client and releases its ports.

The GUI provides a service catalog, local endpoint copying, connection setup, a full JSON editor, and logs. Opening a profile connects all enabled services. The last profile is remembered and connects when the program launches. Windows supports start-in-tray, show/connect/disconnect/quit, and one desktop instance per user. Starting a second instance shows the existing window. Linux/macOS minimize the window instead of using a native tray. The app does not install a Windows login task or OS service.

`Start.cmd` uses `pythonw.exe` without a console. Windows preferences/startup logs live under `%LOCALAPPDATA%\sservcli`; Linux/macOS preferences use `$XDG_CONFIG_HOME/sservcli` or `~/.config/sservcli`. SSH logs are visible in the app.

For a quick initial profile using an administrator-supplied host public key:

```sh
python -m sservcli init --host your-server.example --user existing-account \
  --host-key server-host-key.pub --identity ~/.ssh/sservcli \
  --fallback-hosts 192.0.2.20,192.0.2.21 --config services.json
```

`init` creates one web service, refuses to overwrite a file, and does not provision the server. Omitting `--identity` selects Agent/default identities. `command` prints the OpenSSH command for known-hosts profiles; pinned profiles use `connect`, which owns their temporary verification file and cleanup.

## Server administration

Generate missing server host keys and read the **public** key:

```sh
sudo ssh-keygen -A
cat /etc/ssh/ssh_host_ed25519_key.pub
```

Never distribute `/etc/ssh/ssh_host_ed25519_key`, which is private. Obtain/verify the public key through a trusted administrator channel; an unverified `ssh-keyscan` result does not establish trust. A server host key identifies the server and does not grant login access.

Preview or manage only the SSH policy:

```sh
make render CONFIG=services.json
sudo python3 server/sservcli_server.py install --config services.json \
  --public-key /path/to/sservcli.pub --ensure-ssh
sudo python3 server/sservcli_server.py audit --config services.json
sudo python3 server/sservcli_server.py remove --user svc_tunnel
```

The helper validates SSH config before reload, audits effective restrictions, publishes credentials only after policy activation, and rolls back failed provisioning. Managed metadata lives in `/var/lib/sservcli`. Removal refuses unexpected edits and denies login before account cleanup.

The account requires public-key authentication, `MaxSessions 0`, local TCP forwarding, and an exact loopback `PermitOpen` allowlist. It denies shell/exec/SFTP, remote forwarding, agent/X11/socket forwarding, tunnels, and password/keyboard-interactive authentication. Key options add destination restrictions. Enforcement belongs to `sshd`; see the [OpenSSH configuration manual](https://man.openbsd.org/sshd_config).

The helper does not install or start your web/DB/API services. Keep them bound to loopback where appropriate, expose SSH through the firewall, and ensure other SSH `Match` rules are compatible. The helper audits the effective policy before accepting the account.

Explicit Make administration shortcuts also remain:

```sh
sudo make create TUNNEL_USER=svc_tunnel PUBKEY_FILE=/path/to/sservcli.pub \
  PERMIT_OPEN="127.0.0.1:8080 127.0.0.1:5432"
sudo make audit TUNNEL_USER=svc_tunnel PERMIT_OPEN="127.0.0.1:8080 127.0.0.1:5432"
sudo make delete TUNNEL_USER=svc_tunnel
```

`bundle` gets its account/destinations from `CONFIG`, not these shortcut variables.

## Verification and troubleshooting

```sh
make check test
make integration
# Optional Linux GUI checks:
SSERVCLI_GUI_TESTS=1 xvfb-run -a python3 -m unittest discover -s tests -p test_desktop.py -v
```

Unit tests cover configuration, argument handling, bundle contents/checksums, instance notification, TCP tables, and provisioning rollback. Integration tests use isolated temporary `sshd` and real services to verify multiple forwards, host verification, key/Agent authentication, failover, reconnection, access restrictions, and shutdown. They do not modify real server accounts. Native Windows tests exercise listener ownership, child cleanup, tray lifecycle, and Tk widgets in CI.

For `Permission denied (publickey)`, check that the Windows key/Agent matches `PUBKEY_FILE`. For a host key mismatch, verify the new key with the administrator before updating the profile. For an occupied local port, stop the old client or choose another unused port. Diagnose remote service health separately from SSH listener readiness.

For missing Tkinter, repair Python with Tcl/Tk enabled (Ubuntu: `sudo apt-get install python3-tk`). If `py -3` selects an old installation, launch with the full path to Python 3.11+ using `-m sservcli desktop --config services.json`. When tray initialization fails, the app keeps the window accessible. Startup tracebacks from `Start.cmd` are saved to `%LOCALAPPDATA%\sservcli\desktop.log`.
