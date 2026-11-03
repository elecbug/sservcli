#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::Serialize;
use sservcli::{Config, Snapshot, Tunnel};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
};
use tauri::{Manager, State};

#[derive(Default)]
struct AppState {
    profile: Option<PathBuf>,
    config: Option<Config>,
    tunnel: Tunnel,
    restored: bool,
    error: Option<String>,
    quitting: bool,
    connection_id: u64,
}
type Shared = Mutex<AppState>;

#[derive(Serialize)]
struct View {
    path: String,
    config: Option<Config>,
    connection: Snapshot,
    error: Option<String>,
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
        error: state.error.clone(),
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
fn get_state(app: tauri::AppHandle, state: State<Shared>) -> Result<View, String> {
    let mut state = state.lock().map_err(|e| e.to_string())?;
    restore_profile(&app, &mut state)?;
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
fn load_profile(path: String, app: tauri::AppHandle, state: State<Shared>) -> Result<View, String> {
    let mut state = state.lock().map_err(|e| e.to_string())?;
    editable(&state)?;
    let path = fs::canonicalize(path).map_err(|e| e.to_string())?;
    let config = Config::load(&path)?;
    remember_profile(&app, &path)?;
    state.profile = Some(path);
    state.config = Some(config);
    state.error = None;
    Ok(view(&state))
}

#[tauri::command]
fn save_profile(
    path: String,
    text: String,
    app: tauri::AppHandle,
    state: State<Shared>,
) -> Result<View, String> {
    let mut state = state.lock().map_err(|e| e.to_string())?;
    editable(&state)?;
    let config = Config::parse(&text)?;
    persist_profile(PathBuf::from(path), config, &mut state)?;
    remember_profile(&app, state.profile.as_ref().unwrap())?;
    Ok(view(&state))
}

fn persist_profile(path: PathBuf, config: Config, state: &mut AppState) -> Result<(), String> {
    let text = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())? + "\n";
    let path = write_private(path, &text)?;
    state.profile = Some(path);
    state.config = Some(config);
    state.error = None;
    Ok(())
}

fn write_private(path: PathBuf, text: &str) -> Result<PathBuf, String> {
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
            .write_all(text.as_bytes())
            .map_err(|e| e.to_string())?;
        output.sync_all().map_err(|e| e.to_string())?;
        drop(output);
        fs::rename(&temp, &path).map_err(|e| e.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result?;
    Ok(path)
}

fn remember_profile(app: &tauri::AppHandle, path: &Path) -> Result<(), String> {
    let directory = app.path().app_config_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
    let path = fs::canonicalize(path).map_err(|e| e.to_string())?;
    write_private(
        directory.join("last-profile.json"),
        &serde_json::to_string(&path).map_err(|e| e.to_string())?,
    )?;
    Ok(())
}

fn restore_profile(app: &tauri::AppHandle, state: &mut AppState) -> Result<(), String> {
    if state.restored {
        return Ok(());
    }
    state.restored = true;
    let directory = app.path().app_config_dir().map_err(|e| e.to_string())?;
    let bookmark = directory.join("last-profile.json");
    let arguments: Vec<_> = std::env::args().collect();
    let bundled = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|parent| parent.join("services.json")))
        .filter(|path| path.is_file());
    let path = if let Some(path) = launch_profile(&arguments)? {
        path
    } else if let Some(path) = bundled {
        path
    } else if bookmark.is_file() {
        serde_json::from_str::<PathBuf>(&fs::read_to_string(bookmark).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?
    } else {
        directory.join("connection.json")
    };
    if path.is_file() {
        state.config = Some(Config::load(&path)?);
        state.profile = Some(fs::canonicalize(&path).map_err(|e| e.to_string())?);
        remember_profile(app, state.profile.as_ref().unwrap())?;
    } else if path != directory.join("connection.json") {
        return Err(format!(
            "Saved profile no longer exists: {}",
            path.display()
        ));
    }
    Ok(())
}

fn connect_saved(state: &mut AppState) -> Result<(), String> {
    let config = state
        .config
        .as_ref()
        .ok_or("Set up or load a connection first")?
        .resolved(state.profile.as_ref().ok_or("No profile path")?)?;
    state.error = None;
    state.connection_id = state.connection_id.wrapping_add(1);
    state.tunnel.connect(config)
}

#[tauri::command]
fn quick_connect(
    setup: sservcli::setup::ConnectionSetup,
    app: tauri::AppHandle,
    state: State<Shared>,
) -> Result<View, String> {
    let mut state = state.lock().map_err(|e| e.to_string())?;
    editable(&state)?;
    let config = setup.into_config()?;
    // Reject an invalid key blob before replacing the user's saved connection.
    let _checked = sservcli::host_key::PinnedHostKey::prepare(
        &config.ssh.host,
        config.ssh.port,
        config.ssh.host_public_key.as_deref().unwrap(),
    )?;
    let directory = app.path().app_config_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
    let path = state
        .profile
        .clone()
        .unwrap_or_else(|| directory.join("connection.json"));
    persist_profile(path, config, &mut state)?;
    remember_profile(&app, state.profile.as_ref().unwrap())?;
    connect_saved(&mut state)?;
    Ok(view(&state))
}

#[tauri::command]
fn connect(state: State<Shared>) -> Result<View, String> {
    let mut state = state.lock().map_err(|e| e.to_string())?;
    connect_saved(&mut state)?;
    Ok(view(&state))
}

#[tauri::command]
fn disconnect(state: State<Shared>) -> Result<View, String> {
    let mut state = state.lock().map_err(|e| e.to_string())?;
    state.tunnel.disconnect();
    state.error = None;
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
        .plugin(tauri_plugin_single_instance::init(|app, arguments, _| {
            if let Ok(Some(path)) = launch_profile(&arguments) {
                let shared = app.state::<Shared>();
                if let Ok(mut state) = shared.lock() {
                    let path = fs::canonicalize(path);
                    if let Ok(path) = path {
                        if state.profile.as_ref() != Some(&path) {
                            if editable(&state).is_ok() {
                                match Config::load(&path).and_then(|config| { remember_profile(app, &path)?; state.profile = Some(path); state.config = Some(config); connect_saved(&mut state) }) {
                                    Ok(()) => {}, Err(error) => state.error = Some(error),
                                }
                            } else { state.error = Some("A different profile is active. Disconnect before loading another bundle.".into()); }
                        }
                    } else { state.error = Some("The requested profile could not be opened".into()); }
                };
            }
            show_services(app)
        }))
        .manage(Mutex::new(AppState::default()))
        .setup(|app| {
            use tauri::{
                menu::MenuBuilder,
                tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
            };
            let menu = MenuBuilder::new(app)
                .text("show", "Local services…")
                .text("connect", "Connect all services")
                .text("disconnect", "Disconnect")
                .separator()
                .text("quit", "Quit")
                .build()?;
            let icon = app
                .default_window_icon()
                .ok_or("Missing application icon")?
                .clone();
            TrayIconBuilder::with_id("connection")
                .icon(icon)
                .tooltip("sservcli")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "show" => show_services(app),
                    "connect" => {
                        let shared = app.state::<Shared>();
                        if let Ok(mut state) = shared.lock() {
                            if let Err(error) = connect_saved(&mut state) {
                                state.error = Some(error);
                            }
                        }
                        show_services(app);
                    }
                    "disconnect" => {
                        if let Ok(mut state) = app.state::<Shared>().lock() {
                            state.tunnel.disconnect();
                            state.error = None;
                        }
                    }
                    "quit" => {
                        if let Ok(mut state) = app.state::<Shared>().lock() {
                            state.quitting = true;
                        }
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if matches!(
                        event,
                        TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        }
                    ) {
                        show_services(tray.app_handle());
                    }
                })
                .build(app)?;
            let mut visible = false;
            {
                let shared = app.state::<Shared>();
                let mut state = shared.lock().map_err(|e| e.to_string())?;
                match restore_profile(app.handle(), &mut state) {
                    Ok(()) if state.config.is_some() => {
                        if let Err(error) = connect_saved(&mut state) {
                            state.error = Some(error);
                            visible = true;
                        }
                    }
                    Ok(()) => visible = true,
                    Err(error) => {
                        state.error = Some(error);
                        visible = true;
                    }
                }
            }
            if visible {
                show_services(app.handle());
            }
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                let mut previous = (String::new(), 0);
                loop {
                    let shared = handle.state::<Shared>();
                    let (snapshot, count, id) = {
                        let Ok(state) = shared.lock() else {
                            break;
                        };
                        if state.quitting {
                            break;
                        }
                        (
                            state.tunnel.snapshot(),
                            state
                                .config
                                .as_ref()
                                .map_or(0, |c| c.services.iter().filter(|s| s.enabled).count()),
                            state.connection_id,
                        )
                    };
                    let current = (snapshot.status.clone(), id);
                    if current != previous {
                        if let Some(tray) = handle.tray_by_id("connection") {
                            let _ = tray.set_tooltip(Some(format!(
                                "sservcli: {} — {count} services",
                                snapshot.status
                            )));
                        }
                        if snapshot.status == "failed" {
                            show_services(&handle);
                        }
                        previous = current;
                    }
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let shared = window.app_handle().state::<Shared>();
                let quitting = shared.lock().map(|state| state.quitting).unwrap_or(true);
                if !quitting {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_state,
            example_profile,
            load_profile,
            save_profile,
            quick_connect,
            connect,
            disconnect,
            open_service
        ])
        .build(tauri::generate_context!())
        .expect("Could not initialize sservcli")
        .run(|app, event| {
            if matches!(event, tauri::RunEvent::Exit) {
                if let Ok(mut state) = app.state::<Shared>().lock() {
                    state.quitting = true;
                    state.tunnel.disconnect();
                }
            }
        });
}

fn show_services(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn launch_profile(arguments: &[String]) -> Result<Option<PathBuf>, String> {
    if let Some(index) = arguments.iter().position(|argument| argument == "--config") {
        let path = arguments
            .get(index + 1)
            .filter(|p| !p.is_empty() && !p.starts_with("--"))
            .ok_or("--config requires a profile filename")?;
        Ok(Some(PathBuf::from(path)))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launcher_accepts_profile_paths_with_spaces_and_requires_a_value() {
        let args = vec![
            "sservcli-desktop.exe".into(),
            "--config".into(),
            "C:/Users/Name With Space/services.json".into(),
        ];
        assert_eq!(
            launch_profile(&args).unwrap(),
            Some(PathBuf::from(&args[2]))
        );
        assert!(launch_profile(&args[..2]).is_err());
        assert!(launch_profile(&args[..1]).unwrap().is_none());
    }

    #[test]
    fn profile_replacement_updates_the_file_and_the_active_state() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "sservcli-profile-test-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("services.json");
        let mut state = AppState::default();
        let mut config = Config::parse(include_str!("../../../examples/services.json")).unwrap();
        persist_profile(path.clone(), config.clone(), &mut state).unwrap();
        config.name = "Updated connection".into();
        persist_profile(path.clone(), config, &mut state).unwrap();
        assert_eq!(Config::load(&path).unwrap().name, "Updated connection");
        assert_eq!(state.config.as_ref().unwrap().name, "Updated connection");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(directory).unwrap();
    }
}
