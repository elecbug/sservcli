//! Pin a supplied server host public key without modifying the user's SSH files.
use std::{
    fs,
    path::{Path, PathBuf},
    process::Stdio,
    time::{SystemTime, UNIX_EPOCH},
};

pub fn normalize(key: &str) -> Result<String, String> {
    let key = key.trim();
    if key.len() > 16384 || key.contains(['\r', '\n']) {
        return Err("Paste exactly one plain server host public key line".into());
    }
    let mut fields = key.split_whitespace();
    let kind = fields.next().ok_or("Server host public key is required")?;
    let blob = fields
        .next()
        .ok_or("Server host public key is missing its key data")?;
    if ![
        "ssh-ed25519",
        "ssh-rsa",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
    ]
    .contains(&kind)
        || blob.len() < 16
        || !blob
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
    {
        return Err("Use a plain Ed25519, ECDSA, or RSA host public key (type + base64 data); private keys and known_hosts entries are not accepted".into());
    }
    Ok(format!("{kind} {blob}"))
}

pub struct PinnedHostKey {
    directory: PathBuf,
    path: PathBuf,
    pub fingerprint: String,
}

impl PinnedHostKey {
    pub fn prepare(host: &str, port: u16, key: &str) -> Result<Self, String> {
        Self::prepare_hosts(&[host], port, key)
    }

    pub fn prepare_hosts(hosts: &[&str], port: u16, key: &str) -> Result<Self, String> {
        if hosts.is_empty()
            || hosts.len() > 16
            || hosts.iter().any(|host| !crate::config::valid_host(host))
            || port == 0
        {
            return Err("Invalid SSH host or port".into());
        }
        let key = normalize(key)?;
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("sservcli-host-{}-{stamp:x}", std::process::id()));
        let builder = &mut fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&directory)
            .map_err(|e| format!("Cannot create host-key directory: {e}"))?;
        let path = directory.join("known_hosts");
        // Construct the guard before any fallible operation so every error path
        // removes temporary files. It stays alive for all tunnel reconnects.
        let mut pinned = Self {
            directory,
            path,
            fingerprint: String::new(),
        };
        let hostname = hosts
            .iter()
            .map(|host| {
                if port == 22 {
                    (*host).to_owned()
                } else {
                    format!("[{host}]:{port}")
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        fs::write(&pinned.path, format!("{hostname} {key}\n"))
            .map_err(|e| format!("Cannot store server host key: {e}"))?;
        let result = crate::platform::openssh_command("ssh-keygen")
            .args(["-l", "-E", "sha256", "-f"])
            .arg(&pinned.path)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| {
                format!("OpenSSH ssh-keygen is required to validate the host public key: {e}")
            })?;
        if !result.status.success() {
            return Err(
                "Invalid server host public key; copy the complete .pub line from the server"
                    .into(),
            );
        }
        pinned.fingerprint = String::from_utf8_lossy(&result.stdout)
            .split_whitespace()
            .nth(1)
            .filter(|value| value.starts_with("SHA256:"))
            .ok_or("Could not read the server host-key fingerprint")?
            .to_owned();
        Ok(pinned)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PinnedHostKey {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_a_plain_public_key_and_strips_comments() {
        assert_eq!(
            normalize("  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample root@server\n").unwrap(),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample"
        );
    }
    #[test]
    fn rejects_private_keys_known_hosts_options_and_multiple_keys() {
        for value in [
            "",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "server ssh-ed25519 AAAA",
            "@cert-authority server ssh-ed25519 AAAA",
            "ssh-ed25519 ABCD",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5",
        ] {
            assert!(normalize(value).is_err(), "{value}");
        }
    }
}
