"use strict";

const $ = (id) => document.getElementById(id);
const invoke = window.__TAURI__?.core?.invoke;
let current = null;
let rendered = "";
let busy = false;

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
  if (config) $("server-address").textContent = `${config.ssh.user}@${config.ssh.host}:${config.ssh.port}`;
  $("service-count").textContent = config?.services.length ?? 0;
  $("logs").textContent = connection.logs.join("\n") || "No connection activity yet.";
  for (const id of ["save", "load", "example", "profile-path", "profile-editor"]) $(id).disabled = active;
  if (populateEditor && config) {
    $("profile-path").value = view.path;
    $("profile-editor").value = JSON.stringify(config, null, 2);
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

async function poll() {
  try { if (!busy) paint(await invoke("get_state")); }
  catch (error) { notify(String(error)); }
  setTimeout(poll, 750);
}

if (invoke) {
  action(async () => { $("profile-editor").value = await invoke("example_profile"); paint(await invoke("get_state")); });
  setTimeout(poll, 750);
} else {
  notify("Open this interface with the Tauri desktop app to manage SSH connections.");
}
