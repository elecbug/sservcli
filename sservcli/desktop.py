"""Tkinter desktop: service catalog, simple setup, logs, and Windows tray."""
import copy
import json
import os
from pathlib import Path
import queue
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .config import ConfigError, endpoint, load_profile, resolved_profile, save_profile, service_url, validate_profile
from .instance import Instance, state_directory
from .tunnel import Tunnel, launch_service


def quick_profile(host, fallback, port, user, identity, host_key, services):
    config = {"version": 1, "name": host.strip() or "My server", "ssh": {
        "host": host.strip(), "fallback_hosts": json.loads(fallback or "[]"), "port": int(port),
        "user": user.strip(), "identity_file": identity.strip() or None, "host_public_key": host_key.strip()},
        "reconnect": {"enabled": True, "max_attempts": 5, "initial_delay_secs": 2, "max_delay_secs": 30},
        "services": services}
    validate_profile(config)
    return config


class Desktop:
    def __init__(self, root, config_path=None, background=False, *, directory=None, use_tray=True, actions=None):
        self.root = root
        self.directory = Path(directory) if directory else state_directory()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.preferences_path = self.directory / "preferences.json"
        self.preferences = {}
        try:
            value = json.loads(self.preferences_path.read_text(encoding="utf-8"))
            if isinstance(value, dict):
                self.preferences = value
        except (OSError, ValueError):
            pass
        self.tunnel = Tunnel()
        self.actions = actions if actions is not None else queue.Queue()
        self.tray = None
        self.config = None
        self.config_path = None
        self.previous_logs = None
        self.closing = False
        self._poll_id = None
        self._startup_id = None
        self.root.title("sservcli — SSH services")
        self.root.geometry("960x700")
        self.root.minsize(760, 520)
        self.root.protocol("WM_DELETE_WINDOW", self.hide)
        self._widgets()
        if os.name == "nt" and use_tray:
            try:
                from .windows import Tray
                self.tray = Tray(self.actions)
            except OSError as error:
                self.status.set(f"Tray unavailable: {error}. The window will stay accessible.")
        selected = config_path or self.preferences.get("config_path")
        if not selected and (Path.cwd() / "services.json").is_file():
            selected = Path.cwd() / "services.json"
        if selected:
            try:
                self.load(selected)
                self._startup_id = self.root.after(100, self.connect)
                if self.tray and (background or self.preferences.get("start_hidden", False)):
                    self.root.withdraw()
            except (OSError, ValueError) as error:
                self.status.set(str(error))
                self.root.deiconify()
        self._poll_id = self.root.after(150, self.poll)

    def _widgets(self):
        shell = ttk.Frame(self.root, padding=12)
        shell.pack(fill="both", expand=True)
        toolbar = ttk.Frame(shell)
        toolbar.pack(fill="x", pady=(0, 10))
        for text, command in (("Open profile", self.choose_profile), ("New profile", self.new_profile), ("Connect", self.connect),
                              ("Disconnect", self.disconnect), ("Hide", self.hide), ("Quit", self.quit)):
            ttk.Button(toolbar, text=text, command=command).pack(side="left", padx=(0, 6))
        self.hidden = tk.BooleanVar(value=self.preferences.get("start_hidden", False))
        ttk.Checkbutton(toolbar, text="Start in tray", variable=self.hidden, command=self.remember).pack(side="right")
        self.status = tk.StringVar(value="Open services.json or create a connection below.")
        self.profile_label = tk.StringVar(value="No profile selected")
        ttk.Label(shell, textvariable=self.profile_label).pack(anchor="w")
        ttk.Label(shell, textvariable=self.status, wraplength=900).pack(anchor="w", pady=(4, 10))
        self.tabs = ttk.Notebook(shell)
        self.tabs.pack(fill="both", expand=True)
        catalog = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(catalog, text="Services")
        columns = ("name", "kind", "local", "remote", "state")
        self.services = ttk.Treeview(catalog, columns=columns, show="headings", selectmode="browse")
        for name, label, width in zip(columns, ("Service", "Type", "Local address", "Server port", "Status"), (190, 85, 290, 90, 100)):
            self.services.heading(name, text=label)
            self.services.column(name, width=width, minwidth=70)
        self.services.pack(fill="both", expand=True)
        self.services.bind("<Double-1>", lambda _: self.open_service())
        buttons = ttk.Frame(catalog)
        buttons.pack(fill="x", pady=(10, 0))
        ttk.Button(buttons, text="Open service", command=self.open_service).pack(side="left")
        ttk.Button(buttons, text="Copy local address", command=self.copy_address).pack(side="left", padx=6)
        ttk.Label(catalog, text="All enabled services forward together. Ready means the SSH listener is available; services keep their own authentication.", wraplength=850).pack(anchor="w", pady=8)
        self._setup_widgets()
        advanced = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(advanced, text="Profile JSON")
        self.editor = tk.Text(advanced, wrap="none", undo=True)
        self.editor.pack(fill="both", expand=True)
        ttk.Label(advanced, text="Profiles may launch local programs. Import profiles only from administrators you trust.").pack(anchor="w", pady=6)
        ttk.Button(advanced, text="Save and connect", command=self.save_editor).pack(anchor="w")
        logs = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(logs, text="Connection log")
        self.log = tk.Text(logs, wrap="word", state="disabled")
        self.log.pack(fill="both", expand=True)

    def _setup_widgets(self):
        setup = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(setup, text="Connection setup")
        setup.columnconfigure(1, weight=1)
        self.fields = {}
        specifications = (("host", "Server IP / hostname", ""), ("fallback", "Alternative IPs (JSON array)", "[]"),
                          ("port", "SSH port", "22"), ("user", "SSH user", "svc_tunnel"),
                          ("identity", "Private key (blank = SSH Agent)", ""))
        for row, (name, label, default) in enumerate(specifications):
            ttk.Label(setup, text=label).grid(row=row, column=0, sticky="w", padx=(0, 10), pady=4)
            self.fields[name] = tk.StringVar(value=default)
            ttk.Entry(setup, textvariable=self.fields[name]).grid(row=row, column=1, sticky="ew", pady=4)
        ttk.Button(setup, text="Browse", command=self.choose_identity).grid(row=4, column=2, padx=4)
        ttk.Label(setup, text="Server host public key").grid(row=5, column=0, sticky="nw", pady=4)
        self.host_key = tk.Text(setup, height=3, wrap="word")
        self.host_key.grid(row=5, column=1, columnspan=2, sticky="ew", pady=4)
        ttk.Label(setup, text="Paste the server's ssh_host_ed25519_key.pub. Login uses your existing private key or Agent.", wraplength=640).grid(row=6, column=1, columnspan=2, sticky="w", pady=4)
        service_fields = ttk.Frame(setup)
        service_fields.grid(row=7, column=0, columnspan=3, sticky="ew", pady=10)
        self.quick_services = []
        self.quick_controls = []
        for index, (name, remote, local) in enumerate((("Web dashboard", 8080, 18080), ("PostgreSQL", 5432, 15432), ("REST API", 9000, 19000))):
            enabled = tk.BooleanVar(value=True)
            server_port, local_port = tk.StringVar(value=str(remote)), tk.StringVar(value=str(local))
            self.quick_services.append((enabled, server_port, local_port))
            checkbox = ttk.Checkbutton(service_fields, text=name, variable=enabled)
            checkbox.grid(row=index, column=0, sticky="w", padx=(0, 12))
            ttk.Label(service_fields, text="Server port").grid(row=index, column=1)
            remote_entry = ttk.Entry(service_fields, textvariable=server_port, width=8)
            remote_entry.grid(row=index, column=2, padx=6)
            ttk.Label(service_fields, text="Local port").grid(row=index, column=3)
            local_entry = ttk.Entry(service_fields, textvariable=local_port, width=8)
            local_entry.grid(row=index, column=4, padx=6)
            self.quick_controls.append((checkbox, remote_entry, local_entry))
        ttk.Button(setup, text="Save and connect", command=self.save_quick).grid(row=8, column=1, sticky="w", pady=6)
        ttk.Label(setup, text="Edit custom services and launch commands in Profile JSON.").grid(row=9, column=1, sticky="w", pady=4)

    def remember(self):
        self.preferences["start_hidden"] = self.hidden.get()
        if self.config_path:
            self.preferences["config_path"] = str(self.config_path)
        try:
            temporary = self.preferences_path.with_suffix(".tmp")
            temporary.write_text(json.dumps(self.preferences), encoding="utf-8")
            temporary.replace(self.preferences_path)
        except OSError as error:
            self.status.set(f"Cannot save preferences: {error}")

    def load(self, path):
        config = load_profile(path)
        self.disconnect()
        self.config_path = Path(path).expanduser().resolve()
        self.config = config
        self.profile_label.set(f"{config['name']} — {self.config_path}")
        self.editor.delete("1.0", "end")
        self.editor.insert("1.0", json.dumps(config, indent=2, ensure_ascii=False))
        ssh = config["ssh"]
        for field, value in (("host", ssh["host"]), ("fallback", json.dumps(ssh.get("fallback_hosts", []))),
                             ("port", ssh.get("port", 22)), ("user", ssh["user"]), ("identity", ssh.get("identity_file") or "")):
            self.fields[field].set(value)
        self.host_key.delete("1.0", "end")
        self.host_key.insert("1.0", ssh.get("host_public_key", ""))
        for index, identifier in enumerate(("dashboard", "postgres", "api")):
            service = next((service for service in config["services"] if service["id"] == identifier), None)
            enabled, remote, local = self.quick_services[index]
            enabled.set(service.get("enabled", True) if service else False)
            if service:
                remote.set(str(service["remote_port"]))
                local.set(str(service["local_port"]))
            for control in self.quick_controls[index]:
                control.state(["!disabled" if service else "disabled"])
        self.remember()
        self.refresh_services()

    def new_profile(self):
        self.disconnect()
        self.config = self.config_path = None
        self.profile_label.set("New connection")
        for name, value in (("host", ""), ("fallback", "[]"), ("port", "22"), ("user", "svc_tunnel"), ("identity", "")):
            self.fields[name].set(value)
        self.host_key.delete("1.0", "end")
        self.editor.delete("1.0", "end")
        for index, (remote_port, local_port) in enumerate(((8080, 18080), (5432, 15432), (9000, 19000))):
            enabled, remote, local = self.quick_services[index]
            enabled.set(True)
            remote.set(str(remote_port))
            local.set(str(local_port))
            for control in self.quick_controls[index]:
                control.state(["!disabled"])
        self.refresh_services()
        self.tabs.select(1)

    def choose_profile(self):
        path = filedialog.askopenfilename(parent=self.root, title="Open a trusted services profile", filetypes=(("JSON profile", "*.json"), ("All files", "*")))
        if path:
            self.perform(lambda: (self.load(path), self.connect()))

    def choose_identity(self):
        path = filedialog.askopenfilename(parent=self.root, title="Select your existing SSH private key")
        if path:
            self.fields["identity"].set(path)

    def save_config(self, config):
        validate_profile(config)
        path = filedialog.asksaveasfilename(parent=self.root, title="Save connection profile", defaultextension=".json", initialfile="services.json", filetypes=(("JSON profile", "*.json"),))
        if path:
            save_profile(path, config)
            self.load(path)
            self.connect()
            self.tabs.select(0)

    def save_editor(self):
        self.perform(lambda: self.save_config(json.loads(self.editor.get("1.0", "end"))))

    def save_quick(self):
        def save():
            # Preserve arbitrary services and launch commands when editing an imported profile.
            if self.config:
                config = copy.deepcopy(self.config)
                ssh = config["ssh"]
                ssh.update(host=self.fields["host"].get().strip(), fallback_hosts=json.loads(self.fields["fallback"].get()),
                           port=int(self.fields["port"].get()), user=self.fields["user"].get().strip(),
                           identity_file=self.fields["identity"].get().strip() or None)
                key = self.host_key.get("1.0", "end").strip()
                if key:
                    ssh.pop("known_hosts_file", None)
                    ssh["host_public_key"] = key
                for index, identifier in enumerate(("dashboard", "postgres", "api")):
                    service = next((service for service in config["services"] if service["id"] == identifier), None)
                    if service:
                        enabled, remote, local = self.quick_services[index]
                        service.update(enabled=enabled.get(), remote_port=int(remote.get()), local_port=int(local.get()))
            else:
                services = []
                for (enabled, remote, local), identifier, name, kind in zip(self.quick_services, ("dashboard", "postgres", "api"), ("Web dashboard", "PostgreSQL", "REST API"), ("web", "database", "api")):
                    services.append({"id": identifier, "name": name, "kind": kind, "remote_host": "127.0.0.1", "remote_port": int(remote.get()), "local_port": int(local.get()), "enabled": enabled.get()})
                config = quick_profile(*(self.fields[name].get() for name in ("host", "fallback", "port", "user", "identity")), self.host_key.get("1.0", "end"), services)
            self.save_config(config)
        self.perform(save)

    def connect(self):
        def start():
            if not self.config:
                raise ConfigError("Open a profile or create a connection first")
            if self.tunnel.snapshot()["status"] in ("connecting", "connected", "reconnecting"):
                return
            self.tunnel.connect(resolved_profile(self.config, self.config_path))
        self.perform(start)

    def disconnect(self):
        self.tunnel.disconnect()
        self.status.set("Disconnected; local ports released")

    def selected(self):
        selected = self.services.selection()
        if not selected or not self.config:
            raise ConfigError("Select a service first")
        return next(service for service in self.config["services"] if service["id"] == selected[0])

    def open_service(self):
        def open_selected():
            if self.tunnel.snapshot()["status"] != "connected":
                raise ConfigError("Connect before opening a service")
            launch_service(self.selected())
        self.perform(open_selected)

    def copy_address(self):
        def copy_selected():
            service = self.selected()
            value = service_url(service) if service["kind"] in ("web", "api") else endpoint(service)
            self.root.clipboard_clear()
            self.root.clipboard_append(value)
        self.perform(copy_selected)

    def refresh_services(self):
        selected = self.services.selection()
        self.services.delete(*self.services.get_children())
        state = self.tunnel.snapshot()["status"]
        for service in self.config["services"] if self.config else []:
            enabled = service.get("enabled", True)
            address = service_url(service) if service["kind"] in ("web", "api") else endpoint(service)
            self.services.insert("", "end", iid=service["id"], values=(service["name"], service["kind"], address, service["remote_port"], "disabled" if not enabled else "ready" if state == "connected" else state))
        if selected and self.services.exists(selected[0]):
            self.services.selection_set(selected[0])

    def poll(self):
        if self._poll_id:
            self.root.after_cancel(self._poll_id)
            self._poll_id = None
        if self.closing:
            return
        while True:
            try:
                action = self.actions.get_nowait()
            except queue.Empty:
                break
            if action == "show":
                self.show()
            elif action == "connect":
                self.connect()
            elif action == "disconnect":
                self.disconnect()
            elif action == "quit":
                self.quit()
                return
        changed = False
        while True:
            try:
                status, message = self.tunnel.events.get_nowait()
            except queue.Empty:
                break
            self.status.set(f"{status}: {message}")
            if status == "failed":
                self.show()
            changed = True
        if changed:
            self.refresh_services()
        logs = self.tunnel.snapshot()["logs"]
        if logs != self.previous_logs:
            self.log.configure(state="normal")
            self.log.delete("1.0", "end")
            self.log.insert("1.0", "\n".join(logs))
            self.log.see("end")
            self.log.configure(state="disabled")
            self.previous_logs = logs
        self._poll_id = self.root.after(150, self.poll)

    def perform(self, operation):
        try:
            operation()
        except (OSError, ValueError) as error:
            self.status.set(str(error))
            self.show()
            messagebox.showerror("sservcli", str(error), parent=self.root)

    def show(self):
        self.root.deiconify()
        self.root.lift()

    def hide(self):
        if self.tray:
            self.root.withdraw()
        else:
            self.root.iconify()

    def quit(self):
        if self.closing:
            return
        self.closing = True
        for identifier in (self._poll_id, self._startup_id):
            if identifier:
                self.root.after_cancel(identifier)
        self.tunnel.disconnect()
        if self.tray:
            self.tray.close()
        self.root.destroy()


def run(config_path=None, background=False):
    directory = state_directory()
    actions = queue.Queue()
    instance = Instance(directory, actions)
    if not instance.acquire():
        return 0
    application = None
    try:
        root = tk.Tk()
        application = Desktop(root, config_path, background, directory=directory, actions=actions)
        root.mainloop()
        return 0
    finally:
        if application and not application.closing:
            application.quit()
        instance.close()
