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
        println!("sservcli — multiple services, one SSH connection\n\nUsage: sservcli <check|list|command|connect> --config <profile.json> [--open <service-id>]\n\nconnect keeps the tunnel in the foreground; Ctrl+C disconnects.\n--open is only valid with connect. Web/API services open in a browser.\nDatabase/TCP services use the profile's local launch argument array.");
        return Ok(());
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
