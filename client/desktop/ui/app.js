"use strict";

const $ = (id) => document.getElementById(id);
const invoke = window.__TAURI__?.core?.invoke;
let current = null;
let rendered = "";
let busy = false;
let lastError = "";

function addServiceRow(service = {}) {
  const rows = [...$("quick-services").children];
  const used = new Set(rows.map((row) => row.service.id));
  let index = 1;
  while (used.has(`service-${index}`)) index++;
  const row = document.createElement("div");
  row.className = "quick-row";
  row.service = { id: `service-${index}`, name: "Web service", kind: "web", remote_host: "127.0.0.1", remote_port: 8080 + rows.length, local_port: 18080 + rows.length, enabled: true, path: "/", scheme: "http", launch: null, ...service };
  for (const [name, label] of [["name", "Service name"], ["kind", "Service type"], ["remote_port", "Server port"], ["local_port", "Local port"], ["enabled", "Enable service"]]) {
    const input = document.createElement(name === "kind" ? "select" : "input");
    input.dataset.field = name;
    input.setAttribute("aria-label", label);
    if (name === "kind") {
      for (const kind of ["web", "api", "database", "tcp"]) input.add(new Option(kind, kind));
      input.value = row.service.kind;
    } else if (name === "enabled") {
      input.type = "checkbox";
      input.checked = row.service.enabled;
    } else {
      input.required = true;
      input.value = row.service[name];
      if (name.endsWith("port")) { input.type = "number"; input.min = name === "local_port" ? "1024" : "1"; input.max = "65535"; }
    }
    row.append(input);
  }
  const remove = document.createElement("button");
  remove.type = "button";
  remove.textContent = "×";
  remove.setAttribute("aria-label", "Remove service");
  remove.addEventListener("click", () => row.remove());
  row.append(remove);
  $("quick-services").append(row);
}

function fillQuickForm(config) {
  $("quick-host").value = config.ssh.host;
  $("quick-port").value = config.ssh.port;
  $("quick-fallbacks").value = (config.ssh.fallback_hosts ?? []).join(", ");
  $("quick-user").value = config.ssh.user;
  $("quick-identity").value = config.ssh.identity_file ?? "";
  $("quick-host-key").value = config.ssh.host_public_key ?? "";
  $("quick-services").replaceChildren();
  for (const service of config.services) addServiceRow(service);
}

function tab(name) {
  for (const section of document.querySelectorAll(".tab")) section.hidden = section.id !== name;
  for (const button of document.querySelectorAll(".nav")) button.classList.toggle("active", button.dataset.tab === name);
}
for (const button of document.querySelectorAll(".nav")) button.addEventListener("click", () => tab(button.dataset.tab));
$("get-started").addEventListener("click", () => tab("settings"));

function notify(message, success = false) {
  $("notification").textContent = message;
  $("notification").classList.toggle("success", success);
  $("notification").hidden = false;
}

async function action(work) {
  if (busy) return;
  busy = true;
  try { $("notification").hidden = true; await work(); }
  catch (error) { notify(String(error)); }
  finally { busy = false; }
}

function paint(view, populateEditor = false) {
  current = view;
  const { config, connection } = view;
  const active = ["connecting", "connected", "reconnecting"].includes(connection.status);
  const ready = connection.status === "connected";
  $("workspace").textContent = config?.name ?? "No profile loaded";
  $("badge").textContent = connection.status[0].toUpperCase() + connection.status.slice(1);
  $("badge").className = `badge ${connection.status}`;
  $("connection").textContent = active ? "Disconnect" : "Connect server";
  $("connection").disabled = !config;
  $("connection-message").textContent = connection.message;
  if (config) $("server-address").textContent = `${config.ssh.user}@${connection.active_host ?? config.ssh.host}:${config.ssh.port}`;
  $("server-fingerprint").hidden = !active || !connection.host_key_fingerprint;
  $("server-fingerprint").textContent = connection.host_key_fingerprint ? `Pinned host key: ${connection.host_key_fingerprint}` : "";
  if (view.error && view.error !== lastError) { notify(view.error); lastError = view.error; }
  if (!view.error) lastError = "";
  $("service-count").textContent = config?.services.length ?? 0;
  $("logs").textContent = connection.logs.join("\n") || "No connection activity yet.";
  for (const id of ["save", "load", "example", "profile-path", "profile-editor"]) $(id).disabled = active;
  for (const field of $("quick-form").querySelectorAll("input,textarea,select,button")) field.disabled = active;
  if (populateEditor && config) {
    $("profile-path").value = view.path;
    $("profile-editor").value = JSON.stringify(config, null, 2);
    fillQuickForm(config);
    for (const field of $("quick-form").querySelectorAll("input,textarea,select,button")) field.disabled = active;
  }
  const key = JSON.stringify([config, ready]);
  if (key === rendered || !config) return;
  rendered = key;
  $("service-grid").replaceChildren();
  for (const service of config.services) {
    const card = document.createElement("article");
    card.className = `service ${service.kind}`;
    const top = document.createElement("div");
    top.className = "service-top";
    const icon = document.createElement("span");
    icon.className = "service-icon";
    icon.textContent = ({ web: "◫", database: "▤", api: "{}", tcp: "⇄" })[service.kind];
    const status = document.createElement("span");
    status.className = `service-status ${ready && service.enabled ? "ready" : ""}`;
    status.textContent = !service.enabled ? "Disabled" : ready ? "● Forwarding" : "○ Disconnected";
    top.append(icon, status);
    const name = document.createElement("h3");
    name.textContent = service.name;
    const endpoint = document.createElement("div");
    endpoint.className = "endpoint";
    const web = ["web", "api"].includes(service.kind);
    endpoint.textContent = web ? `${service.scheme ?? "http"}://127.0.0.1:${service.local_port}${service.path}` : `127.0.0.1:${service.local_port}`;
    const remote = document.createElement("div");
    remote.className = "remote";
    remote.textContent = `↳ server ${service.remote_host}:${service.remote_port}`;
    const open = document.createElement("button");
    open.textContent = web ? "Open service ↗" : "Launch client ↗";
    open.disabled = !ready || !service.enabled || (!web && !service.launch);
    open.addEventListener("click", () => action(() => invoke("open_service", { id: service.id })));
    card.append(top, name, endpoint, remote, open);
    $("service-grid").append(card);
  }
}

$("connection").addEventListener("click", () => action(async () => {
  const active = ["connecting", "connected", "reconnecting"].includes(current.connection.status);
  paint(await invoke(active ? "disconnect" : "connect"));
}));
$("load").addEventListener("click", () => action(async () => {
  paint(await invoke("load_profile", { path: $("profile-path").value.trim() }), true);
  notify("Profile loaded. You can connect from Services.", true);
}));
$("save").addEventListener("click", () => action(async () => {
  paint(await invoke("save_profile", { path: $("profile-path").value.trim(), text: $("profile-editor").value }), true);
  notify("Profile validated and saved.", true);
}));
$("example").addEventListener("click", () => action(async () => {
  $("profile-editor").value = await invoke("example_profile");
}));

$("add-service").addEventListener("click", () => addServiceRow());
$("quick-form").addEventListener("submit", (event) => {
  event.preventDefault();
  action(async () => {
    const services = [...$("quick-services").children].map((row) => {
      const service = { ...row.service };
      for (const field of row.querySelectorAll("[data-field]")) {
        const name = field.dataset.field;
        service[name] = name === "enabled" ? field.checked : name.endsWith("port") ? Number(field.value) : field.value;
      }
      return service;
    });
    if (!services.length) throw new Error("Add at least one service.");
    const setup = { host: $("quick-host").value.trim(), port: Number($("quick-port").value),
      fallback_hosts: $("quick-fallbacks").value.split(/[\s,]+/).filter(Boolean), user: $("quick-user").value.trim(),
      identity_file: $("quick-identity").value.trim() || null, host_public_key: $("quick-host-key").value, services };
    paint(await invoke("quick_connect", { setup }), true);
    tab("services");
  });
});

async function poll() {
  try { if (!busy) paint(await invoke("get_state")); }
  catch (error) { notify(String(error)); }
  setTimeout(poll, 750);
}

if (invoke) {
  action(async () => { $("profile-editor").value = await invoke("example_profile"); const view = await invoke("get_state"); paint(view, true); if (!view.config) tab("settings"); });
  setTimeout(poll, 750);
} else {
  notify("Open this interface with the Tauri desktop app to manage SSH connections.");
}
addServiceRow({ id: "dashboard", name: "Web dashboard" });
