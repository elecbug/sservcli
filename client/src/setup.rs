use crate::{
    config::{Reconnect, Ssh},
    Config, Service,
};
use serde::Deserialize;

/// The simple form reuses an existing SSH account and its authorized identity.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionSetup {
    pub host: String,
    #[serde(default)]
    pub fallback_hosts: Vec<String>,
    pub port: u16,
    pub user: String,
    pub host_public_key: String,
    pub identity_file: Option<String>,
    pub services: Vec<Service>,
}

impl ConnectionSetup {
    pub fn into_config(self) -> Result<Config, String> {
        let host = self.host.trim().to_owned();
        let user = self.user.trim().to_owned();
        let identity_file = self
            .identity_file
            .map(|p| p.trim().to_owned())
            .filter(|p| !p.is_empty());
        let config = Config {
            version: 1,
            name: format!("{user}@{host}"),
            ssh: Ssh {
                host,
                fallback_hosts: self
                    .fallback_hosts
                    .into_iter()
                    .map(|h| h.trim().to_owned())
                    .collect(),
                port: self.port,
                user,
                identity_file,
                known_hosts_file: None,
                host_public_key: Some(crate::host_key::normalize(&self.host_public_key)?),
            },
            reconnect: Reconnect::default(),
            services: self.services,
        };
        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn simple_setup_keeps_an_existing_account_and_uses_agent_when_key_path_is_empty() {
        let example = Config::parse(include_str!("../examples/services.json")).unwrap();
        let config = ConnectionSetup {
            host: " server.example.com ".into(),
            fallback_hosts: vec![" 192.0.2.10 ".into()],
            port: 22,
            user: " ubuntu ".into(),
            host_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample comment".into(),
            identity_file: Some(" ".into()),
            services: example.services,
        }
        .into_config()
        .unwrap();
        assert_eq!(config.ssh.user, "ubuntu");
        assert!(config.ssh.identity_file.is_none());
        assert!(config.ssh.known_hosts_file.is_none());
        assert!(Config::parse(&serde_json::to_string(&config).unwrap()).is_ok());
    }
}
