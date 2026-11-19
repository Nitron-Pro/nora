//! Remote file layer: protocol-agnostic `RemoteFs` trait, connection registry and IPC commands.
//!
//! Protocols: SFTP (`sftp.rs`, russh), FTP / explicit FTPS (`ftp.rs`, suppaftp).
//! Transfers (queue, progress events) live in `transfer.rs`; the shared SSH connector in
//! `ssh_common.rs`.
//!
//! Conventions
//! * All IPC commands return `Result<T, String>`; the string is a human readable message that may
//!   start with a machine readable prefix: `CONN_LOST:`, `AUTH_FAILED:`, `HOSTKEY_UNKNOWN:<fp>`,
//!   `HOSTKEY_CHANGED:<fp>`, `CANCELLED`, `TOO_LARGE:`, `UNSUPPORTED:`, `INVALID:`, `NOT_FOUND:`,
//!   `EXISTS:`.
//! * Remote paths are always POSIX style (`/a/b`), UTF-8 strings; CR/LF/NUL are rejected.
//! * Secrets never cross the IPC boundary: profiles carry vault ids (`secret_ref`) only.
//! * Struct fields are serialized in snake_case; Tauri command *arguments* are camelCase on the
//!   JS side (`connId`).

pub mod ftp;
pub mod sftp;
pub mod ssh_common;
pub mod transfer;

use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;

/// Hard cap for `read_small_file` / `write_small_file` (enforced in Rust).
pub const SMALL_FILE_LIMIT: u64 = 2 * 1024 * 1024;
/// Maximum number of simultaneously open remote connections.
pub const MAX_CONNECTIONS: usize = 16;
/// A transfer that makes no progress for this long is treated as a dropped connection.
pub const IO_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Interval of the background keepalive task.
const KEEPALIVE_EVERY: Duration = Duration::from_secs(25);

// ---------------------------------------------------------------------------------------------
// Public data types
// ---------------------------------------------------------------------------------------------

/// Connection profile sent by the UI. Contains NO secrets, only vault ids.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteProfile {
    /// "sftp" | "ftp" | "ftps" (explicit FTPS, AUTH TLS)
    pub protocol: String,
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub username: String,
    /// "password" (default) | "key" (SFTP only)
    #[serde(default)]
    pub auth: Option<String>,
    /// Vault id of the password / PEM private key. FTP: empty => anonymous login.
    #[serde(default)]
    pub secret_ref: Option<String>,
    /// Vault id of the private key passphrase (SFTP key auth).
    #[serde(default)]
    pub passphrase_ref: Option<String>,
    /// FTPS only: accept invalid / self-signed certificates (explicit UI opt-in).
    #[serde(default)]
    pub trust_invalid_cert: bool,
    /// FTP only: legacy code page used when the server lacks UTF8 (e.g. "windows-1256").
    #[serde(default)]
    pub legacy_encoding: Option<String>,
    /// FTP only: passive mode (default true).
    #[serde(default)]
    pub passive: Option<bool>,
    #[serde(default)]
    pub connect_timeout_secs: Option<u64>,
}

impl RemoteProfile {
    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or(match self.protocol.as_str() {
            "sftp" => 22,
            _ => 21,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        if !matches!(self.protocol.as_str(), "sftp" | "ftp" | "ftps") {
            return Err(format!("INVALID: unknown protocol '{}'", self.protocol));
        }
        let h = self.host.trim();
        if h.is_empty() || h.len() > 255 || h.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err("INVALID: bad host".into());
        }
        if self.effective_port() == 0 {
            return Err("INVALID: bad port".into());
        }
        if self.username.len() > 256 || self.username.chars().any(|c| c == '\r' || c == '\n' || c == '\0') {
            return Err("INVALID: bad username".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capabilities {
    pub server_side_copy: bool,
    pub exec: bool,
    pub hash: bool,
    pub chmod: bool,
    pub symlinks: bool,
    pub utf8_names: bool,
    pub resume: bool,
    pub mlsd: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtocolInfo {
    pub protocol: String,
    pub banner: Option<String>,
    /// Initial / home directory.
    pub home: Option<String>,
    pub tls: bool,
    /// FTP: effective name encoding ("utf-8" or the legacy code page).
    pub encoding: Option<String>,
    /// SFTP: SHA256 fingerprint of the verified host key.
    pub host_key_fingerprint: Option<String>,
}

/// One directory entry. `kind`: "file" | "dir" | "symlink" | "other".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteEntry {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub size: u64,
    /// Unix seconds.
    pub modified: Option<i64>,
    /// POSIX mode bits (e.g. 0o644) when known.
    pub permissions: Option<u32>,
    pub link_target: Option<String>,
    /// For symlinks: whether the target is a directory (when resolvable).
    pub target_is_dir: Option<bool>,
}

impl RemoteEntry {
    pub fn is_dir(&self) -> bool {
        self.kind == "dir" || (self.kind == "symlink" && self.target_is_dir == Some(true))
    }
}

/// Byte counter callback: receives the total number of bytes transferred so far
/// (including a resumed offset).
pub type ProgressFn<'a> = &'a (dyn Fn(u64) + Send + Sync);

#[async_trait]
pub trait RemoteFs: Send + Sync {
    fn capabilities(&self) -> Capabilities;
    /// True when several transfers can safely share this one connection (SFTP).
    /// False => the transfer queue leases a dedicated extra connection per transfer (FTP).
    fn parallel_safe(&self) -> bool {
        false
    }
    /// False after a transfer was aborted mid-stream and the connection state is unknown.
    fn is_healthy(&self) -> bool {
        true
    }
    /// Cheap liveness probe (keepalive). Must return `CONN_LOST:` errors for dead links.
    async fn ping(&self) -> Result<(), String>;
    async fn list(&self, path: &str) -> Result<Vec<RemoteEntry>, String>;
    async fn stat(&self, path: &str) -> Result<RemoteEntry, String>;
    /// Download to `local` (parent dirs are created). With `resume`, continues a partial local
    /// file when the remote supports it. Returns the final byte count.
    async fn download(
        &self,
        remote: &str,
        local: &Path,
        resume: bool,
        progress: ProgressFn<'_>,
        cancel: &CancellationToken,
    ) -> Result<u64, String>;
    /// Upload `local` to `remote`, overwriting. With `resume`, appends to a shorter remote file.
    async fn upload(
        &self,
        local: &Path,
        remote: &str,
        resume: bool,
        progress: ProgressFn<'_>,
        cancel: &CancellationToken,
    ) -> Result<u64, String>;
    async fn mkdir(&self, path: &str, recursive: bool) -> Result<(), String>;
    async fn rename(&self, from: &str, to: &str) -> Result<(), String>;
    async fn delete(&self, path: &str, recursive: bool) -> Result<(), String>;
    async fn chmod(&self, path: &str, mode: u32) -> Result<(), String>;
    async fn read_small_file(&self, path: &str) -> Result<Vec<u8>, String>;
    async fn write_small_file(&self, path: &str, data: &[u8]) -> Result<(), String>;
    /// Hex digest computed server side (`algo`: "sha256"). Default: unsupported.
    async fn hash(&self, _path: &str, _algo: &str) -> Result<String, String> {
        Err("UNSUPPORTED: server side hashing".into())
    }
    async fn close(&self);
}

// ---------------------------------------------------------------------------------------------
// Pure helpers (path handling, error classification) - unit tested below
// ---------------------------------------------------------------------------------------------

pub fn conn_lost(msg: impl std::fmt::Display) -> String {
    format!("CONN_LOST: {msg}")
}

pub fn is_conn_lost(err: &str) -> bool {
    err.starts_with("CONN_LOST")
}

/// Reject paths that could smuggle protocol commands (FTP) or are absurd.
pub fn validate_remote_path(p: &str) -> Result<(), String> {
    if p.is_empty() {
        return Err("INVALID: empty remote path".into());
    }
    if p.len() > 4096 || p.chars().any(|c| c == '\0' || c == '\r' || c == '\n') {
        return Err("INVALID: bad remote path".into());
    }
    Ok(())
}

/// Join a POSIX directory and a child name.
pub fn join_path(base: &str, name: &str) -> String {
    if name.starts_with('/') {
        return name.to_string();
    }
    if base.is_empty() {
        return name.to_string();
    }
    if base.ends_with('/') {
        format!("{base}{name}")
    } else {
        format!("{base}/{name}")
    }
}

/// Parent directory of a POSIX path ("/" for top level, "." for bare relative names).
pub fn parent_path(p: &str) -> String {
    let t = p.trim_end_matches('/');
    match t.rfind('/') {
        Some(0) => "/".to_string(),
        Some(i) => t[..i].to_string(),
        None => if p.starts_with('/') { "/".into() } else { ".".into() },
    }
}

/// Last component of a POSIX path.
pub fn base_name(p: &str) -> String {
    let t = p.trim_end_matches('/');
    match t.rfind('/') {
        Some(i) => t[i + 1..].to_string(),
        None => t.to_string(),
    }
}

/// Collapse `//`, `.` and `..` lexically (never escapes the root of an absolute path).
pub fn normalize_path(p: &str) -> String {
    let abs = p.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if !out.is_empty() && *out.last().unwrap() != ".." {
                    out.pop();
                } else if !abs {
                    out.push("..");
                }
            }
            s => out.push(s),
        }
    }
    let joined = out.join("/");
    if abs {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".into()
    } else {
        joined
    }
}

/// Prefixes of an absolute path for recursive mkdir: "/a/b/c" -> ["/a", "/a/b", "/a/b/c"].
pub fn path_prefixes(p: &str) -> Vec<String> {
    let abs = p.starts_with('/');
    let mut acc = String::new();
    let mut v = Vec::new();
    for seg in p.split('/').filter(|s| !s.is_empty() && *s != ".") {
        if acc.is_empty() {
            acc = if abs { format!("/{seg}") } else { seg.to_string() };
        } else {
            acc = format!("{acc}/{seg}");
        }
        v.push(acc.clone());
    }
    v
}

/// A remote name is only safe to map onto the local disk if it is a single, plain component.
/// A malicious server could otherwise send `..\..\evil` or `C:\x`.
pub fn is_safe_local_component(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." || name.len() > 255 {
        return false;
    }
    !name.chars().any(|c| {
        c == '/' || c == '\\' || c == ':' || c == '\0' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|' || c.is_control()
    }) && !name.ends_with('.') && !name.ends_with(' ')
}

pub fn unix_secs(t: std::time::SystemTime) -> Option<i64> {
    t.duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_secs() as i64)
}

/// Open the local destination of a download. Returns (file, resume offset).
pub(crate) async fn open_local_download(
    local: &Path,
    resume: bool,
    remote_size: Option<u64>,
) -> Result<(tokio::fs::File, u64), String> {
    if let Some(parent) = local.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| format!("cannot create local folder: {e}"))?;
        }
    }
    let mut offset = 0u64;
    if resume {
        if let (Ok(md), Some(rs)) = (tokio::fs::metadata(local).await, remote_size) {
            if md.is_file() && md.len() > 0 && md.len() <= rs {
                offset = md.len();
            }
        }
    }
    let f = if offset > 0 {
        tokio::fs::OpenOptions::new()
            .append(true)
            .open(local)
            .await
    } else {
        tokio::fs::File::create(local).await
    }
    .map_err(|e| format!("cannot open local file: {e}"))?;
    Ok((f, offset))
}

/// Copy `reader` to `writer` in 256 KiB chunks with cancellation, idle timeout and progress.
/// `remote_reads`: true when the *reader* is the remote side (download), so that read errors are
/// classified as connection loss and write errors as local I/O errors (and vice versa).
pub(crate) async fn pump<R, W>(
    reader: &mut R,
    writer: &mut W,
    start: u64,
    progress: ProgressFn<'_>,
    cancel: &CancellationToken,
    remote_reads: bool,
) -> Result<u64, String>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut buf = vec![0u8; 256 * 1024];
    let mut total = start;
    loop {
        let n = tokio::select! {
            _ = cancel.cancelled() => return Err("CANCELLED".into()),
            r = tokio::time::timeout(IO_IDLE_TIMEOUT, reader.read(&mut buf)) => match r {
                Err(_) => return Err(conn_lost("transfer stalled (idle timeout)")),
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(if remote_reads { conn_lost(e) } else { format!("local read error: {e}") }),
            },
        };
        if n == 0 {
            break;
        }
        tokio::select! {
            _ = cancel.cancelled() => return Err("CANCELLED".into()),
            r = tokio::time::timeout(IO_IDLE_TIMEOUT, writer.write_all(&buf[..n])) => match r {
                Err(_) => return Err(conn_lost("transfer stalled (idle timeout)")),
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(if remote_reads { format!("local write error: {e}") } else { conn_lost(e) }),
            },
        }
        total += n as u64;
        progress(total);
    }
    Ok(total)
}

// ---------------------------------------------------------------------------------------------
// Connection registry
// ---------------------------------------------------------------------------------------------

/// One open remote connection plus its pool of extra transfer connections.
pub struct ConnEntry {
    pub id: String,
    pub profile: RemoteProfile,
    pub info: ProtocolInfo,
    pub caps: Capabilities,
    primary: RwLock<Arc<dyn RemoteFs>>,
    idle: Mutex<Vec<Arc<dyn RemoteFs>>>,
    reconnect_lock: Mutex<()>,
    keepalive: StdMutex<Option<tokio::task::JoinHandle<()>>>,
}

/// A connection leased to one transfer. Return it with [`ConnEntry::release`].
pub struct Lease {
    pub fs: Arc<dyn RemoteFs>,
    pooled: bool,
}

impl ConnEntry {
    pub async fn primary(&self) -> Arc<dyn RemoteFs> {
        self.primary.read().await.clone()
    }

    /// Replace the primary connection if `stale` is still the current one (transparent reconnect).
    pub async fn reconnect(&self, app: &AppHandle, stale: &Arc<dyn RemoteFs>) -> Result<(), String> {
        let _g = self.reconnect_lock.lock().await;
        if !Arc::ptr_eq(&*self.primary.read().await, stale) {
            return Ok(()); // someone else already reconnected
        }
        emit_conn_state(app, &self.id, "reconnecting", None);
        let old_idle: Vec<_> = self.idle.lock().await.drain(..).collect();
        for f in old_idle {
            f.close().await;
        }
        match connect_fs(app, &self.profile).await {
            Ok((fs, _)) => {
                let old = std::mem::replace(&mut *self.primary.write().await, fs);
                old.close().await;
                emit_conn_state(app, &self.id, "connected", None);
                Ok(())
            }
            Err(e) => {
                emit_conn_state(app, &self.id, "lost", Some(&e));
                Err(e)
            }
        }
    }

    /// Run `f` against the primary connection; on `CONN_LOST` reconnect once and retry.
    pub async fn run<T, F, Fut>(&self, app: &AppHandle, f: F) -> Result<T, String>
    where
        F: Fn(Arc<dyn RemoteFs>) -> Fut,
        Fut: Future<Output = Result<T, String>>,
    {
        let fs = self.primary().await;
        match f(fs.clone()).await {
            Err(e) if is_conn_lost(&e) => {
                self.reconnect(app, &fs).await?;
                f(self.primary().await).await
            }
            other => other,
        }
    }

    /// Lease a connection for a transfer: the shared primary for parallel-safe protocols,
    /// otherwise an idle pooled one (or a fresh extra connection).
    pub async fn lease(&self, app: &AppHandle) -> Result<Lease, String> {
        let primary = self.primary().await;
        if primary.parallel_safe() {
            return Ok(Lease { fs: primary, pooled: false });
        }
        if let Some(fs) = self.idle.lock().await.pop() {
            return Ok(Lease { fs, pooled: true });
        }
        let (fs, _) = connect_fs(app, &self.profile).await?;
        Ok(Lease { fs, pooled: true })
    }

    pub async fn release(&self, lease: Lease, healthy: bool) {
        if !lease.pooled {
            return;
        }
        if healthy && lease.fs.is_healthy() {
            let mut idle = self.idle.lock().await;
            if idle.len() < 8 {
                idle.push(lease.fs);
                return;
            }
        }
        lease.fs.close().await;
    }

    async fn shutdown(&self) {
        if let Some(h) = self.keepalive.lock().unwrap().take() {
            h.abort();
        }
        let idle: Vec<_> = self.idle.lock().await.drain(..).collect();
        for f in idle {
            f.close().await;
        }
        self.primary().await.close().await;
    }
}

#[derive(Default)]
pub struct RemoteManager {
    conns: StdMutex<HashMap<String, Arc<ConnEntry>>>,
}

static MANAGER: OnceLock<RemoteManager> = OnceLock::new();

/// Process-wide registry (no `lib.rs` registration needed).
pub fn manager() -> &'static RemoteManager {
    MANAGER.get_or_init(RemoteManager::default)
}

impl RemoteManager {
    pub fn get(&self, conn_id: &str) -> Result<Arc<ConnEntry>, String> {
        self.conns
            .lock()
            .unwrap()
            .get(conn_id)
            .cloned()
            .ok_or_else(|| format!("NOT_FOUND: unknown connection '{conn_id}'"))
    }
}

fn emit_conn_state(app: &AppHandle, conn_id: &str, state: &str, error: Option<&str>) {
    let _ = app.emit(
        "remote://connection-state",
        serde_json::json!({ "conn_id": conn_id, "state": state, "error": error }),
    );
}

/// Open a brand-new protocol connection from a profile.
pub async fn connect_fs(
    app: &AppHandle,
    profile: &RemoteProfile,
) -> Result<(Arc<dyn RemoteFs>, ProtocolInfo), String> {
    profile.validate()?;
    match profile.protocol.as_str() {
        "sftp" => sftp::connect(app, profile).await,
        _ => ftp::connect(app, profile).await,
    }
}

fn spawn_keepalive(app: AppHandle, entry: &Arc<ConnEntry>) {
    let weak = Arc::downgrade(entry);
    let h = tokio::spawn(async move {
        loop {
            tokio::time::sleep(KEEPALIVE_EVERY).await;
            let Some(e) = weak.upgrade() else { break };
            let fs = e.primary().await;
            if let Err(err) = fs.ping().await {
                if is_conn_lost(&err) {
                    let _ = e.reconnect(&app, &fs).await;
                }
            }
        }
    });
    *entry.keepalive.lock().unwrap() = Some(h);
}

// ---------------------------------------------------------------------------------------------
// IPC commands
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct ConnectResult {
    pub conn_id: String,
    pub capabilities: Capabilities,
    pub protocol_info: ProtocolInfo,
}

#[tauri::command]
pub async fn remote_connect(app: AppHandle, profile: RemoteProfile) -> Result<ConnectResult, String> {
    if manager().conns.lock().unwrap().len() >= MAX_CONNECTIONS {
        return Err("INVALID: too many open connections".into());
    }
    let (fs, info) = connect_fs(&app, &profile).await?;
    let caps = fs.capabilities();
    let id = uuid::Uuid::new_v4().to_string();
    let entry = Arc::new(ConnEntry {
        id: id.clone(),
        profile,
        info: info.clone(),
        caps,
        primary: RwLock::new(fs),
        idle: Mutex::new(Vec::new()),
        reconnect_lock: Mutex::new(()),
        keepalive: StdMutex::new(None),
    });
    spawn_keepalive(app.clone(), &entry);
    manager().conns.lock().unwrap().insert(id.clone(), entry);
    Ok(ConnectResult { conn_id: id, capabilities: caps, protocol_info: info })
}

#[tauri::command]
pub async fn remote_disconnect(conn_id: String) -> Result<(), String> {
    transfer::cancel_connection(&conn_id);
    let entry = manager().conns.lock().unwrap().remove(&conn_id);
    if let Some(e) = entry {
        e.shutdown().await;
    }
    Ok(())
}

#[tauri::command]
pub async fn remote_capabilities(conn_id: String) -> Result<Capabilities, String> {
    Ok(manager().get(&conn_id)?.caps)
}

#[tauri::command]
pub async fn remote_list(app: AppHandle, conn_id: String, path: String) -> Result<Vec<RemoteEntry>, String> {
    validate_remote_path(&path)?;
    let e = manager().get(&conn_id)?;
    e.run(&app, |fs| {
        let p = path.clone();
        async move { fs.list(&p).await }
    })
    .await
}

#[tauri::command]
pub async fn remote_stat(app: AppHandle, conn_id: String, path: String) -> Result<RemoteEntry, String> {
    validate_remote_path(&path)?;
    let e = manager().get(&conn_id)?;
    e.run(&app, |fs| {
        let p = path.clone();
        async move { fs.stat(&p).await }
    })
    .await
}

#[tauri::command]
pub async fn remote_mkdir(app: AppHandle, conn_id: String, path: String, recursive: Option<bool>) -> Result<(), String> {
    validate_remote_path(&path)?;
    let rec = recursive.unwrap_or(false);
    let e = manager().get(&conn_id)?;
    e.run(&app, |fs| {
        let p = path.clone();
        async move { fs.mkdir(&p, rec).await }
    })
    .await
}

#[tauri::command]
pub async fn remote_rename(app: AppHandle, conn_id: String, from: String, to: String) -> Result<(), String> {
    validate_remote_path(&from)?;
    validate_remote_path(&to)?;
    let e = manager().get(&conn_id)?;
    e.run(&app, |fs| {
        let (a, b) = (from.clone(), to.clone());
        async move { fs.rename(&a, &b).await }
    })
    .await
}

#[tauri::command]
pub async fn remote_delete(app: AppHandle, conn_id: String, path: String, recursive: Option<bool>) -> Result<(), String> {
    validate_remote_path(&path)?;
    let norm = normalize_path(&path);
    if norm == "/" || norm == "." {
        return Err("INVALID: refusing to delete the root directory".into());
    }
    let rec = recursive.unwrap_or(false);
    let e = manager().get(&conn_id)?;
    e.run(&app, |fs| {
        let p = path.clone();
        async move { fs.delete(&p, rec).await }
    })
    .await
}

/// `mode` is the numeric POSIX mode (e.g. 420 for 0o644). Masked to 0o7777.
#[tauri::command]
pub async fn remote_chmod(app: AppHandle, conn_id: String, path: String, mode: u32) -> Result<(), String> {
    validate_remote_path(&path)?;
    let mode = mode & 0o7777;
    let e = manager().get(&conn_id)?;
    if !e.caps.chmod {
        return Err("UNSUPPORTED: chmod".into());
    }
    e.run(&app, |fs| {
        let p = path.clone();
        async move { fs.chmod(&p, mode).await }
    })
    .await
}

#[derive(Debug, Serialize)]
pub struct ReadFileResult {
    pub size: u64,
    pub base64: String,
    /// Present when the content is valid UTF-8.
    pub text: Option<String>,
}

#[tauri::command]
pub async fn remote_read_file(app: AppHandle, conn_id: String, path: String) -> Result<ReadFileResult, String> {
    validate_remote_path(&path)?;
    let e = manager().get(&conn_id)?;
    let data = e
        .run(&app, |fs| {
            let p = path.clone();
            async move { fs.read_small_file(&p).await }
        })
        .await?;
    Ok(ReadFileResult {
        size: data.len() as u64,
        base64: base64::engine::general_purpose::STANDARD.encode(&data),
        text: String::from_utf8(data).ok(),
    })
}

/// `encoding`: "utf8" (default, `content` is text) or "base64" (`content` is base64 of the bytes).
#[tauri::command]
pub async fn remote_write_file(
    app: AppHandle,
    conn_id: String,
    path: String,
    content: String,
    encoding: Option<String>,
) -> Result<(), String> {
    validate_remote_path(&path)?;
    let bytes = match encoding.as_deref().unwrap_or("utf8") {
        "utf8" => content.into_bytes(),
        "base64" => base64::engine::general_purpose::STANDARD
            .decode(content.as_bytes())
            .map_err(|e| format!("INVALID: bad base64: {e}"))?,
        other => return Err(format!("INVALID: unknown encoding '{other}'")),
    };
    if bytes.len() as u64 > SMALL_FILE_LIMIT {
        return Err(format!("TOO_LARGE: limit is {SMALL_FILE_LIMIT} bytes"));
    }
    let bytes = Arc::new(bytes);
    let e = manager().get(&conn_id)?;
    e.run(&app, |fs| {
        let (p, b) = (path.clone(), bytes.clone());
        async move { fs.write_small_file(&p, &b).await }
    })
    .await
}

/// Server-side hash (hex). `algo` defaults to "sha256". Errors with `UNSUPPORTED:` when unavailable.
#[tauri::command]
pub async fn remote_hash(app: AppHandle, conn_id: String, path: String, algo: Option<String>) -> Result<String, String> {
    validate_remote_path(&path)?;
    let algo = algo.unwrap_or_else(|| "sha256".into());
    if algo != "sha256" {
        return Err("UNSUPPORTED: only sha256".into());
    }
    let e = manager().get(&conn_id)?;
    if !e.caps.hash {
        return Err("UNSUPPORTED: hash".into());
    }
    e.run(&app, |fs| {
        let (p, a) = (path.clone(), algo.clone());
        async move { fs.hash(&p, &a).await }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_and_parent() {
        assert_eq!(join_path("/a", "b"), "/a/b");
        assert_eq!(join_path("/a/", "b"), "/a/b");
        assert_eq!(join_path("/", "b"), "/b");
        assert_eq!(join_path("/a", "/x"), "/x");
        assert_eq!(parent_path("/a/b"), "/a");
        assert_eq!(parent_path("/a"), "/");
        assert_eq!(parent_path("/"), "/");
        assert_eq!(parent_path("a"), ".");
        assert_eq!(base_name("/a/b/"), "b");
    }

    #[test]
    fn normalize() {
        assert_eq!(normalize_path("/a/./b//c/.."), "/a/b");
        assert_eq!(normalize_path("/../.."), "/");
        assert_eq!(normalize_path("a/../.."), "..");
        assert_eq!(normalize_path(""), ".");
    }

    #[test]
    fn prefixes() {
        assert_eq!(path_prefixes("/a/b/c"), vec!["/a", "/a/b", "/a/b/c"]);
        assert_eq!(path_prefixes("a/b"), vec!["a", "a/b"]);
    }

    #[test]
    fn safe_components() {
        assert!(is_safe_local_component("report.pdf"));
        assert!(is_safe_local_component("فایل.txt"));
        assert!(!is_safe_local_component(".."));
        assert!(!is_safe_local_component("a/b"));
        assert!(!is_safe_local_component("a\\b"));
        assert!(!is_safe_local_component("C:evil"));
        assert!(!is_safe_local_component("x\0"));
    }

    #[test]
    fn path_validation() {
        assert!(validate_remote_path("/ok/path").is_ok());
        assert!(validate_remote_path("/a\r\nDELE x").is_err());
        assert!(validate_remote_path("").is_err());
    }

    #[test]
    fn profile_validation() {
        let mut p = RemoteProfile {
            protocol: "sftp".into(),
            host: "example.com".into(),
            port: None,
            username: "u".into(),
            auth: None,
            secret_ref: None,
            passphrase_ref: None,
            trust_invalid_cert: false,
            legacy_encoding: None,
            passive: None,
            connect_timeout_secs: None,
        };
        assert!(p.validate().is_ok());
        assert_eq!(p.effective_port(), 22);
        p.protocol = "ftp".into();
        assert_eq!(p.effective_port(), 21);
        p.host = "bad host".into();
        assert!(p.validate().is_err());
    }
}
