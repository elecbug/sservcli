use crate::{Config, Service};
use serde::Serialize;
use std::{
    collections::VecDeque,
    fs,
    io::{BufRead, BufReader, Read},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{mpsc, Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub status: String,
    pub attempt: u32,
    pub message: String,
    pub logs: VecDeque<String>,
}

impl Default for Snapshot {
    fn default() -> Self {
        Self {
            status: "disconnected".into(),
            attempt: 0,
            message: "No SSH connection".into(),
            logs: VecDeque::new(),
        }
    }
}

#[derive(Default)]
pub struct Tunnel {
    state: Arc<Mutex<Snapshot>>,
    stop: Option<mpsc::Sender<()>>,
    worker: Option<JoinHandle<()>>,
}

fn update(state: &Mutex<Snapshot>, status: &str, message: impl Into<String>, attempt: u32) {
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    s.status = status.into();
    s.message = message.into();
    s.attempt = attempt;
    let message = s.message.clone();
    s.logs.push_back(message);
    while s.logs.len() > 200 {
        s.logs.pop_front();
    }
}

impl Tunnel {
    pub fn snapshot(&self) -> Snapshot {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn connect(&mut self, config: Config) -> Result<(), String> {
        if !cfg!(unix) {
            return Err("This MVP requires Linux or macOS OpenSSH control sockets".into());
        }
        config.validate()?;
        if self.worker.as_ref().is_some_and(|w| !w.is_finished()) {
            return Err("Disconnect the current connection first".into());
        }
        self.disconnect();
        if !Path::new(&config.ssh.known_hosts_file).is_file() {
            return Err(
                "known_hosts_file is missing; install a verified server host key first".into(),
            );
        }
        if let Some(path) = &config.ssh.identity_file {
            if !Path::new(path).is_file() {
                return Err(format!("Identity file does not exist: {path}"));
            }
        }
        if !Command::new("ssh")
            .arg("-V")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| format!("OpenSSH is required: {e}"))?
            .success()
        {
            return Err("Could not run OpenSSH".into());
        }
        check_ports(&config)?;
        let directory = ControlDirectory::new()?;
        let (tx, rx) = mpsc::channel();
        let state = self.state.clone();
        update(
            &state,
            "connecting",
            "Authenticating and opening local listeners…",
            0,
        );
        self.worker = Some(thread::spawn(move || {
            supervise(config, directory, state, rx)
        }));
        self.stop = Some(tx);
        Ok(())
    }

    pub fn disconnect(&mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        let attempt = self.snapshot().attempt;
        update(
            &self.state,
            "disconnected",
            "SSH connection closed; local listeners released",
            attempt,
        );
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.disconnect();
    }
}

fn check_ports(config: &Config) -> Result<(), String> {
    let mut listeners = Vec::new();
    for service in config.services.iter().filter(|s| s.enabled) {
        listeners.push(
            TcpListener::bind(("127.0.0.1", service.local_port)).map_err(|e| {
                format!(
                    "{}: local port {} is unavailable: {e}",
                    service.id, service.local_port
                )
            })?,
        );
    }
    if listeners.is_empty() {
        return Err("Enable at least one service before connecting".into());
    }
    Ok(())
}

/// No user or system ssh_config is loaded; no shell interprets these arguments.
pub fn ssh_args(config: &Config, control: Option<&Path>) -> Vec<String> {
    let mut args = vec![
        "-F".into(),
        "none".into(),
        "-N".into(),
        "-T".into(),
        "-n".into(),
    ];
    for option in [
        "BatchMode=yes",
        "StrictHostKeyChecking=yes",
        "GlobalKnownHostsFile=none",
        "UpdateHostKeys=no",
        "ExitOnForwardFailure=yes",
        "ServerAliveInterval=20",
        "ServerAliveCountMax=3",
        "ConnectTimeout=10",
        "ConnectionAttempts=1",
        "PreferredAuthentications=publickey",
        "PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no",
        "ForwardAgent=no",
        "ForwardX11=no",
        "GatewayPorts=no",
        "ControlPersist=no",
        "LogLevel=VERBOSE",
    ] {
        args.extend(["-o".into(), option.into()]);
    }
    args.extend([
        "-o".into(),
        format!("UserKnownHostsFile=\"{}\"", config.ssh.known_hosts_file),
    ]);
    if let Some(control) = control {
        args.extend([
            "-M".into(),
            "-S".into(),
            control.to_string_lossy().into_owned(),
        ]);
    } else {
        args.extend([
            "-o".into(),
            "ControlMaster=no".into(),
            "-S".into(),
            "none".into(),
        ]);
    }
    if let Some(identity) = &config.ssh.identity_file {
        args.extend([
            "-o".into(),
            "IdentitiesOnly=yes".into(),
            "-i".into(),
            identity.clone(),
        ]);
    }
    args.extend([
        "-p".into(),
        config.ssh.port.to_string(),
        "-l".into(),
        config.ssh.user.clone(),
    ]);
    for service in config.services.iter().filter(|s| s.enabled) {
        args.extend([
            "-L".into(),
            format!(
                "127.0.0.1:{}:{}:{}",
                service.local_port, service.remote_host, service.remote_port
            ),
        ]);
    }
    args.push(config.ssh.host.clone());
    args
}

struct ControlDirectory(PathBuf);
impl ControlDirectory {
    fn new() -> Result<Self, String> {
        // Keep the Unix-domain socket below the platform's short pathname limit.
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos();
        let path = PathBuf::from(format!("/tmp/sservcli-{}-{stamp:x}", std::process::id()));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&path)
            .map_err(|e| format!("Cannot create private SSH control directory: {e}"))?;
        Ok(Self(path))
    }
}
impl Drop for ControlDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct SshChild(Child);
impl Drop for SshChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn stopped(rx: &mpsc::Receiver<()>, delay: Duration) -> bool {
    !matches!(rx.recv_timeout(delay), Err(mpsc::RecvTimeoutError::Timeout))
}

fn supervise(
    config: Config,
    directory: ControlDirectory,
    state: Arc<Mutex<Snapshot>>,
    stop: mpsc::Receiver<()>,
) {
    let socket = directory.0.join("ssh");
    let mut retries = 0;
    loop {
        if stopped(&stop, Duration::ZERO) {
            break;
        }
        if let Err(e) = check_ports(&config) {
            update(&state, "failed", e, retries);
            return;
        }
        let _ = fs::remove_file(&socket);
        let outcome = run_connection(&config, &socket, &state, &stop, retries);
        match outcome {
            Ok(()) => break,
            Err((message, was_connected)) => {
                // Never retry a first authentication/host-key/bind failure. Retry only
                // an interrupted established connection, or its subsequent recovery.
                if !config.reconnect.enabled
                    || (!was_connected && retries == 0)
                    || retries >= config.reconnect.max_attempts
                {
                    update(&state, "failed", message, retries);
                    return;
                }
                retries += 1;
                let delay = config
                    .reconnect
                    .initial_delay_secs
                    .saturating_mul(1_u64 << (retries - 1).min(20))
                    .min(config.reconnect.max_delay_secs);
                update(
                    &state,
                    "reconnecting",
                    format!(
                        "{message}; retry {retries}/{} in {delay}s",
                        config.reconnect.max_attempts
                    ),
                    retries,
                );
                if stopped(&stop, Duration::from_secs(delay)) {
                    break;
                }
                update(
                    &state,
                    "connecting",
                    "Re-establishing SSH connection…",
                    retries,
                );
            }
        }
    }
    update(
        &state,
        "disconnected",
        "SSH connection closed; local listeners released",
        retries,
    );
}

fn run_connection(
    config: &Config,
    socket: &Path,
    state: &Arc<Mutex<Snapshot>>,
    stop: &mpsc::Receiver<()>,
    attempt: u32,
) -> Result<(), (String, bool)> {
    let child = Command::new("ssh")
        .args(ssh_args(config, Some(socket)))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| (format!("Cannot start SSH: {e}"), false))?;
    let mut child = SshChild(child);
    let stderr = child.0.stderr.take().unwrap();
    let logs = state.clone();
    let reader = thread::spawn(move || {
        // take() bounds even a maliciously long server banner; keep draining
        // stderr for the whole process lifetime without blocking SSH.
        let mut input = BufReader::new(stderr);
        loop {
            let mut line = String::new();
            match input.by_ref().take(4096).read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let line: String = line
                        .trim_end()
                        .chars()
                        .filter(|c| !c.is_control())
                        .collect();
                    let mut s = logs.lock().unwrap_or_else(|e| e.into_inner());
                    s.logs.push_back(line);
                    while s.logs.len() > 200 {
                        s.logs.pop_front();
                    }
                }
            }
        }
    });
    let started = Instant::now();
    let mut connected = false;
    let result = loop {
        if stopped(stop, Duration::from_millis(200)) {
            break Ok(());
        }
        match child.0.try_wait() {
            Ok(Some(exit)) => {
                break Err((
                    format!("SSH exited with {exit}; see connection log"),
                    connected,
                ))
            }
            Err(e) => break Err((format!("Cannot inspect SSH process: {e}"), connected)),
            _ => {}
        }
        if !connected && socket.exists() {
            let ready = Command::new("ssh")
                .args(["-F", "none", "-S"])
                .arg(socket)
                .args(["-O", "check", &config.ssh.host])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            if ready.is_ok_and(|s| s.success()) {
                connected = true;
                update(
                    state,
                    "connected",
                    "SSH authenticated; local listeners ready (service health is not checked)",
                    attempt,
                );
            }
        }
        if !connected && started.elapsed() > Duration::from_secs(20) {
            break Err(("SSH startup timed out; see connection log".into(), false));
        }
    };
    drop(child);
    let _ = reader.join();
    result
}

/// Profiles are trusted local code: launch arrays name local executables.
/// Service credentials stay in the service's own client/keychain, never here.
pub fn launch(service: &Service) -> Result<(), String> {
    if !service.enabled {
        return Err("Enable and connect this service first".into());
    }
    let argv = service.launch_argv()?;
    // Terminal applications (e.g. psql) inherit CLI stdio. A desktop user should
    // configure a terminal emulator or GUI client in the launch array.
    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        .spawn()
        .map_err(|e| format!("Cannot launch {}: {e}", argv[0]))?;
    thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn arguments_enforce_security_and_use_one_process_for_multiple_services() {
        let mut config = Config::parse(include_str!("../examples/services.json")).unwrap();
        config.services[2].enabled = false;
        let args = ssh_args(&config, None);
        assert!(args.contains(&"StrictHostKeyChecking=yes".into()));
        assert!(args.contains(&"BatchMode=yes".into()));
        assert_eq!(&args[..2], ["-F", "none"]);
        assert_eq!(args.iter().filter(|a| *a == "-L").count(), 2);
        assert!(args.contains(&"127.0.0.1:15432:127.0.0.1:5432".into()));
        assert_eq!(args.last().unwrap(), "server.example.com");
    }
    #[test]
    fn occupied_ports_and_all_disabled_are_rejected() {
        let mut config = Config::parse(include_str!("../examples/services.json")).unwrap();
        for s in &mut config.services {
            s.enabled = false;
        }
        assert!(check_ports(&config).is_err());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        config.services[0].enabled = true;
        config.services[0].local_port = listener.local_addr().unwrap().port();
        assert!(check_ports(&config).unwrap_err().contains("unavailable"));
    }
    #[test]
    fn control_directory_is_private_and_removed() {
        let path;
        {
            let dir = ControlDirectory::new().unwrap();
            path = dir.0.clone();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o700
                );
            }
        }
        assert!(!path.exists());
    }
}
