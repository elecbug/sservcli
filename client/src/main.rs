use sservcli::{config::Kind, platform, tunnel::ssh_args, Config, Tunnel};
use std::{path::PathBuf, thread, time::Duration};

fn main() {
    let result = run();
    platform::shutdown_complete();
    if let Err(e) = result {
        eprintln!("sservcli: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args == ["--help"] || args == ["-h"] {
        println!("sservcli — multiple services, one SSH connection\n\nFirst connection:\n  sservcli init --host <server> --user <existing-user> --host-key <server.pub> [--identity <key>]\n  Optional: --fallback-hosts <IP,IP> --config <profile.json> --port <22> --remote-port <8080> --local-port <18080>\n\nUsage: sservcli <check|list|command|connect> --config <profile.json> [--open <service-id>]\n\ninit writes a new profile (default: services.json) without changing the server.\nWithout --identity, authentication uses your SSH Agent or default SSH identities.\nconnect keeps the tunnel in the foreground; Ctrl+C disconnects.\n--open is only valid with connect. Web/API services open in a browser.\nDatabase/TCP services use the profile's local launch argument array.");
        return Ok(());
    }
    if args[0] == "init" {
        return init_profile(&args[1..]);
    }
    let command = &args[0];
    if !["check", "list", "command", "connect"].contains(&command.as_str()) {
        return Err(format!("Unknown command: {command}; use --help"));
    }
    let mut profile = None;
    let mut open = None;
    let mut options = args[1..].chunks_exact(2);
    for pair in options.by_ref() {
        match pair[0].as_str() {
            "--config" if profile.is_none() => profile = Some(PathBuf::from(&pair[1])),
            "--open" if open.is_none() && command == "connect" => open = Some(pair[1].clone()),
            option => return Err(format!("Unexpected or duplicate option: {option}")),
        }
    }
    if !options.remainder().is_empty() {
        return Err("Each option requires a value".into());
    }
    let profile = profile.ok_or("Pass --config <profile.json>")?;
    let config = Config::load(&profile)?;
    if command == "check" {
        println!(
            "Valid profile: {} ({} services)",
            config.name,
            config.services.len()
        );
        return Ok(());
    }
    if command == "list" {
        for s in &config.services {
            let address = if matches!(s.kind, Kind::Web | Kind::Api) {
                s.url()
            } else {
                format!("127.0.0.1:{}", s.local_port)
            };
            println!(
                "{:<16} {:<8} {:<36} -> {}:{}",
                s.id,
                if s.enabled { "enabled" } else { "disabled" },
                address,
                s.remote_host,
                s.remote_port
            );
        }
        return Ok(());
    }
    let config = config.resolved(&profile)?;
    if command == "command" {
        if config.ssh.host_public_key.is_some() {
            return Err("Use connect with inline host_public_key profiles; it creates and cleans up the pinned host-key file automatically. command is available for known_hosts_file profiles.".into());
        }
        println!("{}", platform::format_ssh_command(&ssh_args(&config, None)));
        return Ok(());
    }
    let service = open
        .as_ref()
        .map(|id| {
            config
                .services
                .iter()
                .find(|s| &s.id == id && s.enabled)
                .cloned()
                .ok_or_else(|| format!("Unknown or disabled service: {id}"))
        })
        .transpose()?;
    platform::install_shutdown_handler()?;
    let mut tunnel = Tunnel::default();
    tunnel.connect(config)?;
    if let Some(fingerprint) = tunnel.snapshot().host_key_fingerprint {
        eprintln!("[pinned host key] {fingerprint}");
    }
    let mut previous = String::new();
    let mut opened = false;
    while !platform::shutdown_requested() {
        let snapshot = tunnel.snapshot();
        if snapshot.message != previous {
            eprintln!("[{}] {}", snapshot.status, snapshot.message);
            previous = snapshot.message;
        }
        if snapshot.status == "failed" {
            for line in snapshot.logs {
                eprintln!("  {line}");
            }
            return Err("Connection failed".into());
        }
        if snapshot.status == "connected" && !opened {
            if let Some(service) = &service {
                sservcli::launch(service)?;
            }
            opened = true;
        }
        thread::sleep(Duration::from_millis(200));
    }
    tunnel.disconnect();
    Ok(())
}

fn init_profile(args: &[String]) -> Result<(), String> {
    use sservcli::{
        config::{Scheme, Service},
        host_key::PinnedHostKey,
        setup::ConnectionSetup,
    };
    use std::{collections::HashMap, fs, io::Write};
    let mut options = HashMap::new();
    let mut pairs = args.chunks_exact(2);
    for pair in pairs.by_ref() {
        if ![
            "--host",
            "--fallback-hosts",
            "--user",
            "--host-key",
            "--identity",
            "--config",
            "--port",
            "--remote-port",
            "--local-port",
        ]
        .contains(&pair[0].as_str())
            || options.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err(format!("Unexpected or duplicate option: {}", pair[0]));
        }
    }
    if !pairs.remainder().is_empty() {
        return Err("Each init option requires a value".into());
    }
    let required = |key| {
        options
            .get(key)
            .copied()
            .ok_or_else(|| format!("init requires {key}"))
    };
    let port = |key, default| {
        options.get(key).map_or(Ok(default), |value| {
            value
                .parse::<u16>()
                .map_err(|_| format!("Invalid port for {key}"))
        })
    };
    let config = ConnectionSetup {
        host: required("--host")?.into(),
        fallback_hosts: options
            .get("--fallback-hosts")
            .map(|v| v.split(',').map(str::to_owned).collect())
            .unwrap_or_default(),
        port: port("--port", 22)?,
        user: required("--user")?.into(),
        host_public_key: fs::read_to_string(required("--host-key")?)
            .map_err(|e| format!("Cannot read server host public key: {e}"))?,
        identity_file: options.get("--identity").map(|p| (*p).to_owned()),
        services: vec![Service {
            id: "dashboard".into(),
            name: "Web service".into(),
            kind: Kind::Web,
            remote_host: "127.0.0.1".into(),
            remote_port: port("--remote-port", 8080)?,
            local_port: port("--local-port", 18080)?,
            enabled: true,
            path: "/".into(),
            scheme: Scheme::Http,
            launch: None,
        }],
    }
    .into_config()?;
    let pinned = PinnedHostKey::prepare(
        &config.ssh.host,
        config.ssh.port,
        config.ssh.host_public_key.as_deref().unwrap(),
    )?;
    let path = PathBuf::from(options.get("--config").copied().unwrap_or("services.json"));
    let mut open = fs::OpenOptions::new();
    open.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(0o600);
    }
    let text = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())? + "\n";
    let mut file = open.open(&path).map_err(|e| {
        format!(
            "Cannot create {} (existing profiles are not overwritten): {e}",
            path.display()
        )
    })?;
    if let Err(error) = file
        .write_all(text.as_bytes())
        .and_then(|_| file.sync_all())
    {
        drop(file);
        let _ = fs::remove_file(&path);
        return Err(format!("Cannot save profile: {error}"));
    }
    println!("Created {}\nPinned server host key: {}\nUse connect --config to start the tunnel. Your existing SSH account must already authorize the selected key/agent and permit TCP forwarding.", path.display(), pinned.fingerprint);
    Ok(())
}
