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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallback_hosts: Vec<String>,
    #[serde(default = "ssh_port")]
    pub port: u16,
    pub user: String,
    pub identity_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_hosts_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_public_key: Option<String>,
}

impl Ssh {
    pub fn hosts(&self) -> Vec<&str> {
        std::iter::once(self.host.as_str())
            .chain(self.fallback_hosts.iter().map(String::as_str))
            .collect()
    }
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

pub(crate) fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('-')
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b))
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
        if !valid_host(host) {
            return Err("ssh.host must be a hostname or an unbracketed IP address".into());
        }
        let hosts = self.ssh.hosts();
        let mut unique = HashSet::new();
        if hosts.len() > 16
            || hosts
                .iter()
                .any(|host| !valid_host(host) || !unique.insert(host.to_ascii_lowercase()))
        {
            return Err("SSH addresses must be valid, unique hostnames/IPs; configure at most 16 including the primary host".into());
        }
        let user = &self.ssh.user;
        if !identifier(user) || user.starts_with('-') || self.ssh.port == 0 {
            return Err("Invalid SSH user or port".into());
        }
        match (&self.ssh.host_public_key, &self.ssh.known_hosts_file) {
            (Some(key), None) => {
                crate::host_key::normalize(key)?;
            }
            (None, Some(_)) => {}
            _ => {
                return Err("Set exactly one of ssh.host_public_key or ssh.known_hosts_file".into())
            }
        }
        for path in self
            .ssh
            .known_hosts_file
            .iter()
            .chain(self.ssh.identity_file.iter())
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
        result.ssh.known_hosts_file = self
            .ssh
            .known_hosts_file
            .as_ref()
            .map(|p| resolve_path(p, base).and_then(|p| crate::platform::ssh_path(&p)))
            .transpose()?;
        result.ssh.identity_file = self
            .ssh
            .identity_file
            .as_ref()
            .map(|p| resolve_path(p, base).and_then(|p| crate::platform::ssh_path(&p)))
            .transpose()?;
        Ok(result)
    }
}

fn resolve_path(value: &str, base: &Path) -> Result<PathBuf, String> {
    #[cfg(windows)]
    let value = value.replace('\\', "/");
    #[cfg(windows)]
    let value = value.as_str();
    if let Some(rest) = value.strip_prefix("~/") {
        let home = crate::platform::home_dir()
            .ok_or("Home directory is not set; use an absolute SSH path")?;
        Ok(PathBuf::from(home).join(rest))
    } else if value.starts_with('~') {
        Err("Only ~/ home expansion is supported".into())
    } else {
        #[cfg(windows)]
        if !Path::new(value).is_absolute()
            && Path::new(value)
                .components()
                .any(|p| matches!(p, std::path::Component::Prefix(_)))
        {
            return Err(
                "Drive-relative SSH paths are unsupported; use C:/path or a profile-relative path"
                    .into(),
            );
        }
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

    /// None selects the platform's default browser; Some contains a local
    /// executable and arguments passed directly to process creation.
    pub fn launch_argv(&self) -> Result<Option<Vec<String>>, String> {
        if let Some(argv) = &self.launch {
            return Ok(Some(
                argv.iter()
                    .map(|arg| {
                        arg.replace("{host}", "127.0.0.1")
                            .replace("{port}", &self.local_port.to_string())
                            .replace("{url}", &self.url())
                    })
                    .collect(),
            ));
        }
        if matches!(self.kind, Kind::Web | Kind::Api) {
            return Ok(None);
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
            c.services[1].launch_argv().unwrap().unwrap(),
            ["psql", "-h", "127.0.0.1", "-p", "15432", "-U", "app", "app"]
        );
    }

    #[test]
    fn default_browser_is_separate_from_local_command_execution() {
        let c = example();
        assert!(c.services[0].launch_argv().unwrap().is_none());
        assert!(c.services[2].launch_argv().unwrap().is_none());
    }

    #[test]
    fn host_key_sources_and_fallback_addresses_are_unambiguous() {
        let mut c = example();
        c.ssh.host_public_key = Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample".into());
        assert!(c.validate().is_err());
        c.ssh.known_hosts_file = None;
        assert!(c.validate().is_ok());
        c.ssh.fallback_hosts = vec![c.ssh.host.clone()];
        assert!(c.validate().is_err());
        c.ssh.fallback_hosts = vec!["192.0.2.10".into(), "192.0.2.11".into()];
        assert!(c.validate().is_ok());
        assert_eq!(
            c.ssh.hosts(),
            ["server.example.com", "192.0.2.10", "192.0.2.11"]
        );
        c.ssh.host_public_key = None;
        assert!(c.validate().is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_home_and_profile_relative_paths() {
        let base = Path::new("C:/Profiles/한 글");
        assert_eq!(
            resolve_path(r".ssh\known_hosts", base).unwrap(),
            base.join(".ssh/known_hosts")
        );
        let expected = PathBuf::from(crate::platform::home_dir().unwrap()).join(".ssh/id_ed25519");
        assert_eq!(resolve_path(r"~\.ssh\id_ed25519", base).unwrap(), expected);
        assert!(resolve_path("C:relative", base).is_err());
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
                5 => c.ssh.known_hosts_file = Some("x\nProxyCommand evil".into()),
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
