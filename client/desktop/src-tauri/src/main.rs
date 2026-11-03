#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::Serialize;
use sservcli::{Config, Snapshot, Tunnel};
use std::{fs, io::Write, path::PathBuf, sync::Mutex};
use tauri::{Manager, State};

#[derive(Default)]
struct AppState {
    profile: Option<PathBuf>,
    config: Option<Config>,
    tunnel: Tunnel,
}
type Shared = Mutex<AppState>;

#[derive(Serialize)]
struct View {
    path: String,
    config: Option<Config>,
    connection: Snapshot,
}

fn view(state: &AppState) -> View {
    View {
        path: state
            .profile
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        config: state.config.clone(),
        connection: state.tunnel.snapshot(),
    }
}

fn editable(state: &AppState) -> Result<(), String> {
    if ["connecting", "connected", "reconnecting"]
        .contains(&state.tunnel.snapshot().status.as_str())
    {
        return Err("Disconnect before loading or changing a profile".into());
    }
    Ok(())
}

#[tauri::command]
fn get_state(state: State<Shared>) -> Result<View, String> {
    let state = state.lock().map_err(|e| e.to_string())?;
    Ok(view(&state))
}

#[tauri::command]
fn example_profile() -> String {
    #[cfg(windows)]
    {
        include_str!("../../../examples/services.windows.json").into()
    }
    #[cfg(not(windows))]
    include_str!("../../../examples/services.json").into()
}

#[tauri::command]
fn load_profile(path: String, state: State<Shared>) -> Result<View, String> {
    let mut state = state.lock().map_err(|e| e.to_string())?;
    editable(&state)?;
    let path = fs::canonicalize(path).map_err(|e| e.to_string())?;
    let config = Config::load(&path)?;
    state.profile = Some(path);
    state.config = Some(config);
    Ok(view(&state))
}

#[tauri::command]
fn save_profile(path: String, text: String, state: State<Shared>) -> Result<View, String> {
    let mut state = state.lock().map_err(|e| e.to_string())?;
    editable(&state)?;
    let config = Config::parse(&text)?;
    let path = PathBuf::from(path);
    if path.file_name().is_none() {
        return Err("Choose a profile filename".into());
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let parent = fs::canonicalize(parent).map_err(|e| e.to_string())?;
    let path = parent.join(path.file_name().unwrap());
    if fs::symlink_metadata(&path).is_ok_and(|m| !m.is_file()) {
        return Err("Profile must be a regular file, not a symbolic link".into());
    }
    let temp = parent.join(format!(".sservcli-{}.tmp", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(&temp).map_err(|e| e.to_string())?;
    let result = (|| {
        output
            .write_all(
                serde_json::to_string_pretty(&config)
                    .map_err(|e| e.to_string())?
                    .as_bytes(),
            )
            .map_err(|e| e.to_string())?;
        output.write_all(b"\n").map_err(|e| e.to_string())?;
        output.sync_all().map_err(|e| e.to_string())?;
        drop(output);
        fs::rename(&temp, &path).map_err(|e| e.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result?;
    state.profile = Some(path);
    state.config = Some(config);
    Ok(view(&state))
}

#[tauri::command]
fn connect(state: State<Shared>) -> Result<View, String> {
    let mut state = state.lock().map_err(|e| e.to_string())?;
    let config = state
        .config
        .as_ref()
        .ok_or("Load a profile first")?
        .resolved(state.profile.as_ref().unwrap())?;
    state.tunnel.connect(config)?;
    Ok(view(&state))
}

#[tauri::command]
fn disconnect(state: State<Shared>) -> Result<View, String> {
    let mut state = state.lock().map_err(|e| e.to_string())?;
    state.tunnel.disconnect();
    Ok(view(&state))
}

#[tauri::command]
fn open_service(id: String, state: State<Shared>) -> Result<(), String> {
    let state = state.lock().map_err(|e| e.to_string())?;
    if state.tunnel.snapshot().status != "connected" {
        return Err("Connect before opening a service".into());
    }
    let service = state
        .config
        .as_ref()
        .ok_or("Load a profile first")?
        .services
        .iter()
        .find(|s| s.id == id)
        .ok_or("Unknown service")?;
    sservcli::launch(service)
}

fn main() {
    tauri::Builder::default()
        .manage(Mutex::new(AppState::default()))
        .invoke_handler(tauri::generate_handler![
            get_state,
            example_profile,
            load_profile,
            save_profile,
            connect,
            disconnect,
            open_service
        ])
        .build(tauri::generate_context!())
        .expect("Could not initialize sservcli")
        .run(|app, event| {
            if matches!(event, tauri::RunEvent::Exit) {
                if let Ok(mut state) = app.state::<Shared>().lock() {
                    state.tunnel.disconnect();
                }
            }
        });
}
