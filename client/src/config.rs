use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub name: String,
    pub ssh: Ssh,
    #[serde(default)]
    pub reconnect: Reconnect,
    pub services: Vec<Service>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ssh {
    pub host: String,
    #[serde(default = "ssh_port")]
    pub port: u16,
    pub user: String,
    pub identity_file: Option<String>,
    pub known_hosts_file: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Reconnect {
    pub enabled: bool,
    pub max_attempts: u32,
    pub initial_delay_secs: u64,
    pub max_delay_secs: u64,
}

impl Default for Reconnect {
    fn default() -> Self {
        Self {
            enabled: true,
            max_attempts: 5,
            initial_delay_secs: 2,
            max_delay_secs: 30,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub id: String,
    pub name: String,
    pub kind: Kind,
    pub remote_host: String,
    pub remote_port: u16,
    pub local_port: u16,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default = "default_path")]
    pub path: String,
    #[serde(default)]
    pub scheme: Scheme,
    pub launch: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Web,
    Api,
    Database,
    Tcp,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    #[default]
    Http,
    Https,
}

fn ssh_port() -> u16 {
    22
}
fn yes() -> bool {
    true
}
fn default_path() -> String {
    "/".into()
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, String> {
        let config: Self =
            serde_json::from_str(text).map_err(|e| format!("Invalid configuration: {e}"))?;
        config.validate()?;
        Ok(config)
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        Self::parse(&fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 {
            return Err("Only configuration version 1 is supported".into());
        }
        if self.name.trim().is_empty() || self.name.len() > 128 {
            return Err("name must contain 1–128 characters".into());
        }
        let host = &self.ssh.host;
        if host.is_empty()
            || host.len() > 253
            || host.starts_with('-')
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b))
        {
            return Err("ssh.host must be a hostname or an unbracketed IP address".into());
        }
        let user = &self.ssh.user;
        if !identifier(user) || user.starts_with('-') || self.ssh.port == 0 {
            return Err("Invalid SSH user or port".into());
        }
        for path in std::iter::once(&self.ssh.known_hosts_file).chain(self.ssh.identity_file.iter())
        {
            if path.is_empty() || path.chars().any(|c| c.is_control() || c == '"' || c == '%') {
                return Err(
                    "SSH paths must be nonempty and contain no controls, quotes, or % tokens"
                        .into(),
                );
            }
        }
        let r = &self.reconnect;
        if r.max_attempts > 100
            || r.initial_delay_secs == 0
            || r.max_delay_secs < r.initial_delay_secs
            || r.max_delay_secs > 300
        {
            return Err(
                "Reconnect requires 0–100 retries and delays between 1 and 300 seconds".into(),
            );
        }
        if self.services.is_empty() || self.services.len() > 64 {
            return Err("Configure between 1 and 64 services".into());
        }
        let mut ids = HashSet::new();
        let mut ports = HashSet::new();
        for s in &self.services {
            if !identifier(&s.id) || !ids.insert(&s.id) || s.name.trim().is_empty() {
                return Err("Services need unique ids and nonempty names".into());
            }
            if s.remote_host != "127.0.0.1"
                || s.remote_port == 0
                || s.local_port < 1024
                || !ports.insert(s.local_port)
            {
                return Err(format!("{}: use remote_host 127.0.0.1, a valid remote port, and a unique local port >= 1024", s.id));
            }
            if !s.path.starts_with('/')
                || s.path.starts_with("//")
                || s.path
                    .chars()
                    .any(|c| c.is_control() || c.is_whitespace() || c == '\\')
            {
                return Err(format!(
                    "{}: path must be an absolute URL path without whitespace or backslashes",
                    s.id
                ));
            }
            if let Some(argv) = &s.launch {
                if argv.is_empty()
                    || argv[0].is_empty()
                    || argv[0].starts_with('-')
                    || argv[0].contains(['{', '}'])
                    || argv.iter().any(|a| a.contains('\0'))
                {
                    return Err(format!(
                        "{}: launch must be a nonempty executable/argument array",
                        s.id
                    ));
                }
                for arg in argv.iter().skip(1) {
                    let rest = arg
                        .replace("{host}", "")
                        .replace("{port}", "")
                        .replace("{url}", "");
                    if rest.contains(['{', '}']) {
                        return Err(format!("{}: unknown launch placeholder", s.id));
                    }
                }
            }
        }
        Ok(())
    }

    /// Resolve paths relative to the profile file, never the process working directory.
    pub fn resolved(&self, profile: &Path) -> Result<Self, String> {
        let base = fs::canonicalize(profile).map_err(|e| format!("{}: {e}", profile.display()))?;
        let base = base.parent().ok_or("Profile has no parent directory")?;
        let mut result = self.clone();
        result.ssh.known_hosts_file = resolve_path(&self.ssh.known_hosts_file, base)?
            .to_string_lossy()
            .into_owned();
        result.ssh.identity_file = self
            .ssh
            .identity_file
            .as_ref()
            .map(|p| resolve_path(p, base).map(|p| p.to_string_lossy().into_owned()))
            .transpose()?;
        Ok(result)
    }
}

fn resolve_path(value: &str, base: &Path) -> Result<PathBuf, String> {
    if let Some(rest) = value.strip_prefix("~/") {
        let home = std::env::var_os("HOME").ok_or("HOME is not set; use an absolute SSH path")?;
        Ok(PathBuf::from(home).join(rest))
    } else if value.starts_with('~') {
        Err("Only ~/ home expansion is supported".into())
    } else {
        Ok(base.join(value))
    }
}

impl Service {
    pub fn url(&self) -> String {
        let scheme = match self.scheme {
            Scheme::Http => "http",
            Scheme::Https => "https",
        };
        format!("{scheme}://127.0.0.1:{}{}", self.local_port, self.path)
    }

    pub fn launch_argv(&self) -> Result<Vec<String>, String> {
        if let Some(argv) = &self.launch {
            return Ok(argv
                .iter()
                .map(|arg| {
                    arg.replace("{host}", "127.0.0.1")
                        .replace("{port}", &self.local_port.to_string())
                        .replace("{url}", &self.url())
                })
                .collect());
        }
        if matches!(self.kind, Kind::Web | Kind::Api) {
            let opener = if cfg!(target_os = "macos") {
                "open"
            } else {
                "xdg-open"
            };
            return Ok(vec![opener.into(), self.url()]);
        }
        Err(format!(
            "{}: configure a launch array for this service",
            self.id
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn example() -> Config {
        Config::parse(include_str!("../examples/services.json")).unwrap()
    }

    #[test]
    fn validates_example_and_expands_argv_without_a_shell() {
        let c = example();
        assert_eq!(c.services[0].url(), "http://127.0.0.1:18080/");
        assert_eq!(
            c.services[1].launch_argv().unwrap(),
            ["psql", "-h", "127.0.0.1", "-p", "15432", "-U", "app", "app"]
        );
    }
    #[test]
    fn rejects_unsafe_or_ambiguous_profiles() {
        for mutation in 0..7 {
            let mut c = example();
            match mutation {
                0 => c.ssh.host = "-oProxyCommand=evil".into(),
                1 => c.services[1].local_port = c.services[0].local_port,
                2 => c.services[0].remote_host = "0.0.0.0".into(),
                3 => c.services[0].path = "//attacker.example".into(),
                4 => c.services[0].launch = Some(vec!["tool".into(), "{password}".into()]),
                5 => c.ssh.known_hosts_file = "x\nProxyCommand evil".into(),
                _ => c.reconnect.max_delay_secs = 0,
            }
            assert!(c.validate().is_err(), "mutation {mutation}");
        }
        assert!(Config::parse(
            &include_str!("../examples/services.json")
                .replace("\"version\": 1", "\"version\": 1, \"typo\": true")
        )
        .is_err());
    }
}
