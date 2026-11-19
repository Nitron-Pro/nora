//! Shared SSH connector (russh) used by SFTP and, later, by the terminal PTY/exec module.
//!
//! # Public Rust API
//! ```text
//! pub struct SshProfile { host, port, username, auth, secret_ref, passphrase_ref,
//!                         connect_timeout_secs, keepalive_secs }          // serde, no secrets
//! pub struct SshHandle  { session: russh::client::Handle<SshClientHandler>,
//!                         host_key_fingerprint: String }                  // Deref -> Handle
//! pub async fn connect_ssh(app: &AppHandle, profile: &SshProfile) -> Result<SshHandle, String>
//! pub async fn exec_collect(h: &SshHandle, cmd: &str, max_out: usize)
//!                         -> Result<ExecOutput { stdout, stderr, exit_status }, String>
//! pub fn trust_host(host: &str, port: u16, fingerprint: &str) -> Result<(), String>
//! pub fn known_fingerprint(host: &str, port: u16) -> Result<Option<String>, String>
//! pub fn shell_quote(s: &str) -> String                                   // POSIX single-quote
//! #[tauri::command] ssh_trust_host(host, port, fingerprint) -> Result<(), String>
//! ```
//!
//! # Error-string conventions (prefix, then free text)
//! * `HOSTKEY_UNKNOWN:<fingerprint>`  - first contact; UI shows the fingerprint and, on consent,
//!   calls `ssh_trust_host` and retries.
//! * `HOSTKEY_CHANGED:<fingerprint> (expected <old>)` - stored key differs (possible MITM).
//!   The UI may call `ssh_trust_host` again to replace the stored key after explicit confirmation.
//! * `AUTH_FAILED: ...`, `CONN_LOST: ...` (network / timeout), `INVALID: ...`.
//!
//! Fingerprints use the OpenSSH form `SHA256:<base64>`. Trusted keys live in
//! `<exe_dir>/nora-data/ssh/known_hosts.json` as `{ "host:port": "SHA256:..." }`.
//! Secrets are fetched from the vault inside this module and never logged or returned.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client;
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::ChannelMsg;
use serde::{Deserialize, Serialize};
use tauri::AppHandle;

use super::{conn_lost, RemoteProfile};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshProfile {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub username: String,
    /// "password" (default) | "key"
    #[serde(default)]
    pub auth: Option<String>,
    /// Vault id of the password or PEM/OpenSSH/PPK private key.
    #[serde(default)]
    pub secret_ref: Option<String>,
    /// Vault id of the key passphrase (key auth only).
    #[serde(default)]
    pub passphrase_ref: Option<String>,
    #[serde(default)]
    pub connect_timeout_secs: Option<u64>,
    /// SSH keepalive interval (default 15 s, 0 disables).
    #[serde(default)]
    pub keepalive_secs: Option<u64>,
}

fn default_port() -> u16 {
    22
}

impl From<&RemoteProfile> for SshProfile {
    fn from(p: &RemoteProfile) -> Self {
        SshProfile {
            host: p.host.trim().to_string(),
            port: p.effective_port(),
            username: p.username.clone(),
            auth: p.auth.clone(),
            secret_ref: p.secret_ref.clone(),
            passphrase_ref: p.passphrase_ref.clone(),
            connect_timeout_secs: p.connect_timeout_secs,
            keepalive_secs: None,
        }
    }
}

/// An authenticated SSH session. Derefs to the underlying russh handle.
pub struct SshHandle {
    pub session: client::Handle<SshClientHandler>,
    pub host_key_fingerprint: String,
}

impl std::ops::Deref for SshHandle {
    type Target = client::Handle<SshClientHandler>;
    fn deref(&self) -> &Self::Target {
        &self.session
    }
}
impl std::ops::DerefMut for SshHandle {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.session
    }
}

// ---------------------------------------------------------------------------------------------
// known_hosts store
// ---------------------------------------------------------------------------------------------

static KNOWN_HOSTS_LOCK: Mutex<()> = Mutex::new(());

fn host_key_id(host: &str, port: u16) -> String {
    format!("{}:{}", host.trim().to_lowercase(), port)
}

fn known_hosts_path() -> Result<std::path::PathBuf, String> {
    Ok(crate::portable::data_subdir("ssh")?.join("known_hosts.json"))
}

fn load_known() -> Result<BTreeMap<String, String>, String> {
    let p = known_hosts_path()?;
    match std::fs::read_to_string(&p) {
        Ok(s) if s.trim().is_empty() => Ok(BTreeMap::new()),
        Ok(s) => serde_json::from_str(&s).map_err(|e| format!("known_hosts.json is corrupt: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(format!("cannot read known_hosts: {e}")),
    }
}

pub fn known_fingerprint(host: &str, port: u16) -> Result<Option<String>, String> {
    let _g = KNOWN_HOSTS_LOCK.lock().unwrap();
    Ok(load_known()?.get(&host_key_id(host, port)).cloned())
}

pub fn valid_fingerprint(fp: &str) -> bool {
    fp.len() <= 128
        && fp.starts_with("SHA256:")
        && fp.len() > 10
        && fp[7..].chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

/// Persist trust for a host key (replaces a previous entry).
pub fn trust_host(host: &str, port: u16, fingerprint: &str) -> Result<(), String> {
    if !valid_fingerprint(fingerprint) {
        return Err("INVALID: fingerprint must look like SHA256:<base64>".into());
    }
    if host.trim().is_empty() || port == 0 {
        return Err("INVALID: bad host/port".into());
    }
    let _g = KNOWN_HOSTS_LOCK.lock().unwrap();
    let mut map = load_known()?;
    map.insert(host_key_id(host, port), fingerprint.to_string());
    let path = known_hosts_path()?;
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_string_pretty(&map).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, json).map_err(|e| format!("cannot write known_hosts: {e}"))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("cannot update known_hosts: {e}"))?;
    Ok(())
}

#[tauri::command]
pub async fn ssh_trust_host(host: String, port: u16, fingerprint: String) -> Result<(), String> {
    trust_host(&host, port, &fingerprint)
}

// ---------------------------------------------------------------------------------------------
// Handler (host key verification)
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    Pending,
    Trusted(String),
    Unknown(String),
    Changed { found: String, expected: String },
}

pub struct SshClientHandler {
    expected: Option<String>,
    verdict: Arc<Mutex<Verdict>>,
}

fn fingerprint_of(key: &PublicKeyOrCertificate) -> String {
    match key {
        PublicKeyOrCertificate::PublicKey { key, .. } => key.fingerprint(HashAlg::Sha256).to_string(),
        PublicKeyOrCertificate::Certificate(c) => c.public_key().fingerprint(HashAlg::Sha256).to_string(),
    }
}

impl client::Handler for SshClientHandler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let fp = fingerprint_of(key);
        let (v, ok) = match &self.expected {
            Some(e) if *e == fp => (Verdict::Trusted(fp), true),
            Some(e) => (Verdict::Changed { found: fp, expected: e.clone() }, false),
            None => (Verdict::Unknown(fp), false),
        };
        *self.verdict.lock().unwrap() = v;
        Ok(ok)
    }
}

fn verdict_error(v: &Verdict) -> Option<String> {
    match v {
        Verdict::Unknown(fp) => Some(format!("HOSTKEY_UNKNOWN:{fp}")),
        Verdict::Changed { found, expected } => Some(format!("HOSTKEY_CHANGED:{found} (expected {expected})")),
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------------
// Connect
// ---------------------------------------------------------------------------------------------

/// Connect, verify the host key, authenticate (password or key from the vault).
pub async fn connect_ssh(app: &AppHandle, profile: &SshProfile) -> Result<SshHandle, String> {
    let host = profile.host.trim().to_string();
    if host.is_empty() || profile.port == 0 || profile.username.is_empty() {
        return Err("INVALID: host, port and username are required".into());
    }
    let timeout = Duration::from_secs(profile.connect_timeout_secs.unwrap_or(15).clamp(3, 120));
    let ka = profile.keepalive_secs.unwrap_or(15);

    let cfg = client::Config {
        keepalive_interval: if ka == 0 { None } else { Some(Duration::from_secs(ka)) },
        keepalive_max: 4,
        inactivity_timeout: None,
        nodelay: true,
        window_size: 4 * 1024 * 1024,
        maximum_packet_size: 64 * 1024,
        ..Default::default()
    };

    let verdict = Arc::new(Mutex::new(Verdict::Pending));
    let handler = SshClientHandler {
        expected: known_fingerprint(&host, profile.port)?,
        verdict: verdict.clone(),
    };

    let connected = tokio::time::timeout(timeout, client::connect(Arc::new(cfg), (host.as_str(), profile.port), handler)).await;
    let mut session = match connected {
        Err(_) => return Err(conn_lost("connection timed out")),
        Ok(Err(e)) => {
            let v = verdict.lock().unwrap().clone();
            return Err(verdict_error(&v).unwrap_or_else(|| conn_lost(e)));
        }
        Ok(Ok(s)) => s,
    };
    let fp = match verdict.lock().unwrap().clone() {
        Verdict::Trusted(fp) => fp,
        other => return Err(verdict_error(&other).unwrap_or_else(|| "HOSTKEY_UNKNOWN:".into())),
    };

    let auth_res = tokio::time::timeout(timeout, authenticate(app, &mut session, profile)).await;
    match auth_res {
        Err(_) => Err(conn_lost("authentication timed out")),
        Ok(Err(e)) => Err(e),
        Ok(Ok(())) => Ok(SshHandle { session, host_key_fingerprint: fp }),
    }
}

async fn authenticate(
    app: &AppHandle,
    session: &mut client::Handle<SshClientHandler>,
    profile: &SshProfile,
) -> Result<(), String> {
    let method = profile.auth.as_deref().unwrap_or("password");
    let secret_id = profile
        .secret_ref
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "INVALID: secret_ref is required".to_string())?;
    let secret = crate::vault::resolve_secret(app, secret_id)?;

    let res = match method {
        "password" => session
            .authenticate_password(profile.username.clone(), secret.as_str())
            .await
            .map_err(|e| conn_lost(e))?,
        "key" => {
            let passphrase = match profile.passphrase_ref.as_deref().filter(|s| !s.is_empty()) {
                Some(id) => Some(crate::vault::resolve_secret(app, id)?),
                None => None,
            };
            let key = russh::keys::decode_secret_key(secret.as_str(), passphrase.as_ref().map(|p| p.as_str()))
                .map_err(|e| format!("AUTH_FAILED: cannot decode private key: {e}"))?;
            let hash = session.best_supported_rsa_hash().await.ok().flatten().flatten();
            session
                .authenticate_publickey(profile.username.clone(), PrivateKeyWithHashAlg::new(Arc::new(key), hash))
                .await
                .map_err(|e| conn_lost(e))?
        }
        other => return Err(format!("INVALID: unknown auth method '{other}'")),
    };
    if res.success() {
        Ok(())
    } else {
        Err("AUTH_FAILED: the server rejected the credentials".into())
    }
}

// ---------------------------------------------------------------------------------------------
// Exec helper
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct ExecOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_status: Option<u32>,
}

/// Run one command on a fresh exec channel and collect its output (capped at `max_out` bytes each).
pub async fn exec_collect(h: &SshHandle, cmd: &str, max_out: usize) -> Result<ExecOutput, String> {
    let mut ch = h.channel_open_session().await.map_err(conn_lost)?;
    ch.exec(true, cmd.as_bytes().to_vec()).await.map_err(conn_lost)?;
    let mut out = ExecOutput::default();
    let fut = async {
        while let Some(msg) = ch.wait().await {
            match msg {
                ChannelMsg::Data { data } => {
                    if out.stdout.len() < max_out {
                        out.stdout.extend_from_slice(&data);
                    }
                }
                ChannelMsg::ExtendedData { data, .. } => {
                    if out.stderr.len() < max_out {
                        out.stderr.extend_from_slice(&data);
                    }
                }
                ChannelMsg::ExitStatus { exit_status } => out.exit_status = Some(exit_status),
                _ => {}
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(120), fut)
        .await
        .map_err(|_| conn_lost("exec timed out"))?;
    Ok(out)
}

/// POSIX single-quote escaping for building safe remote shell commands.
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote("$(rm -rf /)"), "'$(rm -rf /)'");
    }

    #[test]
    fn fingerprint_validation() {
        assert!(valid_fingerprint("SHA256:abcDEF123+/="));
        assert!(!valid_fingerprint("MD5:aa:bb"));
        assert!(!valid_fingerprint("SHA256:"));
        assert!(!valid_fingerprint("SHA256:abc def"));
    }

    #[test]
    fn host_ids() {
        assert_eq!(host_key_id(" Example.COM ", 22), "example.com:22");
    }

    #[test]
    fn verdict_errors() {
        assert_eq!(verdict_error(&Verdict::Unknown("SHA256:x".into())).unwrap(), "HOSTKEY_UNKNOWN:SHA256:x");
        assert!(verdict_error(&Verdict::Changed { found: "SHA256:a".into(), expected: "SHA256:b".into() })
            .unwrap()
            .starts_with("HOSTKEY_CHANGED:SHA256:a"));
        assert!(verdict_error(&Verdict::Pending).is_none());
    }
}
