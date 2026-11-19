//! FTP / explicit FTPS backend (suppaftp + rustls, pure Rust, no OpenSSL).
//!
//! * Passive mode by default, UTF-8 names (OPTS UTF8 ON when FEAT advertises it), otherwise a
//!   configurable legacy code page (default windows-1256, Persian) via `encoding_rs`.
//! * MLSD when advertised (MLST in FEAT), LIST (POSIX/DOS) fallback; resume via REST.
//! * One control connection does one thing at a time (`parallel_safe() == false`); the transfer
//!   queue leases extra connections from the pool for parallel transfers.

use std::path::Path;
use std::pin::Pin;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use suppaftp::list::{File as FtpFile, ListParser, PosixPexQuery};
use suppaftp::tokio::{AsyncRustlsConnector, AsyncRustlsFtpStream};
use suppaftp::types::FileType as FtpFileType;
use suppaftp::{Encoding as FtpEncoding, FtpError, Mode, Utf8Encoding};
use tauri::AppHandle;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use super::*;

type Client = AsyncRustlsFtpStream;

const OP_TIMEOUT: Duration = Duration::from_secs(60);
pub const DEFAULT_LEGACY_ENCODING: &str = "windows-1256";

// ---------------------------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------------------------

/// Decodes names as UTF-8 when valid, otherwise with the legacy code page (so a mixed/unknown
/// server still shows readable names). Encodes outgoing names as UTF-8 or the legacy code page
/// depending on what the server accepts.
#[derive(Debug)]
pub struct AutoEncoding {
    legacy: &'static encoding_rs::Encoding,
    utf8_out: bool,
}

impl FtpEncoding for AutoEncoding {
    fn decode(&self, bytes: &[u8]) -> String {
        match std::str::from_utf8(bytes) {
            Ok(s) => s.to_string(),
            Err(_) => self.legacy.decode_without_bom_handling(bytes).0.into_owned(),
        }
    }

    fn encode(&self, text: &str) -> std::io::Result<Vec<u8>> {
        if self.utf8_out {
            return Ok(text.as_bytes().to_vec());
        }
        let (bytes, _, had_errors) = self.legacy.encode(text);
        if had_errors {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("name cannot be represented in {}", self.legacy.name()),
            ));
        }
        Ok(bytes.into_owned())
    }
}

/// Decide the outgoing encoding. `feat_utf8`: server advertised UTF8 in FEAT.
/// Returns (send names as UTF-8?, legacy encoding used for decode fallback / legacy sending).
pub fn choose_encoding(
    feat_utf8: bool,
    legacy_label: Option<&str>,
) -> Result<(bool, &'static encoding_rs::Encoding), String> {
    let label = legacy_label.map(str::trim).filter(|s| !s.is_empty()).unwrap_or(DEFAULT_LEGACY_ENCODING);
    let enc = encoding_rs::Encoding::for_label(label.as_bytes())
        .ok_or_else(|| format!("INVALID: unknown legacy encoding '{label}'"))?;
    if !enc.is_ascii_compatible() {
        return Err(format!("INVALID: encoding '{label}' is not ASCII compatible"));
    }
    // An explicit "utf-8" label means "never use a legacy code page".
    let utf8_out = feat_utf8 || enc == encoding_rs::UTF_8;
    Ok((utf8_out, enc))
}

// ---------------------------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------------------------

#[derive(Debug)]
struct AcceptAnyCert(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn tls_connector(trust_invalid: bool) -> Result<AsyncRustlsConnector, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS setup failed: {e}"))?;
    let config = if trust_invalid {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    Ok(AsyncRustlsConnector::from(tokio_rustls::TlsConnector::from(Arc::new(config))))
}

// ---------------------------------------------------------------------------------------------
// Errors & parsing
// ---------------------------------------------------------------------------------------------

fn map_ftp_err(e: FtpError) -> String {
    match e {
        FtpError::ConnectionError(io) => conn_lost(io),
        FtpError::SecureError(m) => format!("TLS error: {m}"),
        FtpError::UnexpectedResponse(r) => {
            let code = r.status.code();
            let text = r.as_string().unwrap_or_default();
            match code {
                421 => conn_lost(format!("server closed the connection ({text})")),
                530 => format!("AUTH_FAILED: {text}"),
                550 => format!("FTP 550: {text}"),
                _ => format!("FTP {code}: {text}"),
            }
        }
        FtpError::BadResponse => "FTP: malformed server response".into(),
        other => other.to_string(),
    }
}

fn to_entry(dir: &str, f: &FtpFile) -> Option<RemoteEntry> {
    let name = base_name(f.name());
    if name.is_empty() || name == "." || name == ".." {
        return None;
    }
    let kind = if f.is_directory() {
        "dir"
    } else if f.is_symlink() {
        "symlink"
    } else if f.is_file() {
        "file"
    } else {
        "other"
    };
    let mut mode = 0u32;
    for (q, shift) in [(PosixPexQuery::Owner, 6u32), (PosixPexQuery::Group, 3), (PosixPexQuery::Others, 0)] {
        mode |= ((f.can_read(q) as u32) << 2 | (f.can_write(q) as u32) << 1 | f.can_execute(q) as u32) << shift;
    }
    let modified = unix_secs(f.modified()).filter(|t| *t > 0);
    Some(RemoteEntry {
        path: join_path(dir, &name),
        name,
        kind: kind.into(),
        size: f.size() as u64,
        modified,
        permissions: if mode == 0 { None } else { Some(mode) },
        link_target: f.symlink().map(|p| p.to_string_lossy().into_owned()),
        target_is_dir: None,
    })
}

/// Parse one listing line, trying the format family that matches `mlsd` first.
pub fn parse_list_line(line: &str, mlsd: bool) -> Option<FtpFile> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line.trim().is_empty() {
        return None;
    }
    if mlsd {
        return ListParser::parse_mlsd(line).ok();
    }
    ListParser::parse_posix(line).ok().or_else(|| ListParser::parse_dos(line).ok())
}

#[derive(Clone, Copy)]
struct Flags {
    mlsd: bool,
    mlst: bool,
    size: bool,
    rest: bool,
}

async fn list_raw(c: &mut Client, path: &str, fl: Flags) -> Result<Vec<RemoteEntry>, String> {
    c.cwd(path).await.map_err(map_ftp_err)?;
    let mut lines = None;
    let mut used_mlsd = false;
    if fl.mlsd {
        if let Ok(l) = c.mlsd(None).await {
            lines = Some(l);
            used_mlsd = true;
        }
    }
    let lines = match lines {
        Some(l) => l,
        None => c.list(None).await.map_err(map_ftp_err)?,
    };
    let mut out = Vec::new();
    for l in &lines {
        if let Some(f) = parse_list_line(l, used_mlsd) {
            if let Some(mut e) = to_entry(path, &f) {
                if e.kind == "symlink" {
                    e.target_is_dir = Some(c.cwd(&e.path).await.is_ok());
                }
                out.push(e);
            }
        }
    }
    Ok(out)
}

fn delete_rec<'a>(
    c: &'a mut Client,
    path: &'a str,
    fl: Flags,
) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async move {
        for e in list_raw(c, path, fl).await? {
            if e.kind == "dir" {
                delete_rec(c, &e.path, fl).await?;
            } else {
                c.rm(&e.path).await.map_err(map_ftp_err)?;
            }
        }
        c.rmdir(path).await.map_err(map_ftp_err)
    })
}

// ---------------------------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------------------------

pub struct FtpFs {
    client: Mutex<Option<Client>>,
    fl: Flags,
    utf8: bool,
    healthy: AtomicBool,
}

pub async fn connect(app: &AppHandle, profile: &RemoteProfile) -> Result<(Arc<dyn RemoteFs>, ProtocolInfo), String> {
    let host = profile.host.trim().to_string();
    let port = profile.effective_port();
    let timeout = Duration::from_secs(profile.connect_timeout_secs.unwrap_or(15).clamp(3, 120));
    let ftps = profile.protocol == "ftps";

    let addr = tokio::time::timeout(timeout, tokio::net::lookup_host((host.as_str(), port)))
        .await
        .map_err(|_| conn_lost("DNS lookup timed out"))?
        .map_err(|e| conn_lost(format!("cannot resolve host: {e}")))?
        .next()
        .ok_or_else(|| conn_lost("host has no address"))?;

    let mut ftp = Client::connect_timeout(addr, timeout).await.map_err(map_ftp_err)?;
    ftp.set_passive_nat_workaround(true);
    if profile.passive == Some(false) {
        ftp = ftp.active_mode(Duration::from_secs(30));
    } else {
        ftp.set_mode(Mode::Passive);
    }
    let banner = ftp.get_welcome_msg().map(|s| s.chars().take(300).collect::<String>());

    if ftps {
        let conn = tls_connector(profile.trust_invalid_cert)?;
        ftp = tokio::time::timeout(timeout, ftp.into_secure(conn, &host))
            .await
            .map_err(|_| conn_lost("TLS handshake timed out"))?
            .map_err(|e| match e {
                FtpError::SecureError(m) => format!("TLS error: {m} (self-signed certificate? enable trust_invalid_cert)"),
                other => map_ftp_err(other),
            })?;
    }

    // Login. Empty username => anonymous.
    let (user, pass) = if profile.username.is_empty() {
        ("anonymous".to_string(), zeroize::Zeroizing::new("anonymous@".to_string()))
    } else {
        let pass = match profile.secret_ref.as_deref().filter(|s| !s.is_empty()) {
            Some(id) => crate::vault::resolve_secret(app, id)?,
            None => zeroize::Zeroizing::new(String::new()),
        };
        (profile.username.clone(), pass)
    };
    if pass.contains(['\r', '\n']) || user.contains(['\r', '\n']) {
        return Err("INVALID: credentials contain control characters".into());
    }
    tokio::time::timeout(timeout, ftp.login(user.as_str(), pass.as_str()))
        .await
        .map_err(|_| conn_lost("login timed out"))?
        .map_err(map_ftp_err)?;
    drop(pass);

    ftp.transfer_type(FtpFileType::Binary).await.map_err(map_ftp_err)?;

    let feat = ftp.feat().await.unwrap_or_default();
    let has = |n: &str| feat.keys().any(|k| k.eq_ignore_ascii_case(n));
    let feat_utf8 = has("UTF8");
    let fl = Flags { mlsd: has("MLST"), mlst: has("MLST"), size: has("SIZE"), rest: has("REST") };

    let (utf8_out, legacy) = choose_encoding(feat_utf8, profile.legacy_encoding.as_deref())?;
    if feat_utf8 {
        // Best effort: many servers already default to UTF-8 and reject the command.
        let _ = ftp.opts("UTF8", Some("ON")).await;
    }
    ftp.set_encoding(AutoEncoding { legacy, utf8_out }).await;
    let _ = Utf8Encoding; // (type kept imported for documentation of the default)

    let home = ftp.pwd().await.ok();
    let info = ProtocolInfo {
        protocol: profile.protocol.clone(),
        banner,
        home,
        tls: ftps,
        encoding: Some(if utf8_out { "utf-8".to_string() } else { legacy.name().to_lowercase() }),
        host_key_fingerprint: None,
    };
    let fs = FtpFs { client: Mutex::new(Some(ftp)), fl, utf8: utf8_out, healthy: AtomicBool::new(true) };
    Ok((Arc::new(fs), info))
}

macro_rules! op {
    ($self:ident, $c:ident, $e:expr) => {{
        let mut guard = $self.client.lock().await;
        let $c = guard.as_mut().ok_or_else(|| conn_lost("connection closed"))?;
        match tokio::time::timeout(OP_TIMEOUT, $e).await {
            Err(_) => {
                $self.healthy.store(false, Ordering::Relaxed);
                Err(conn_lost("FTP operation timed out"))
            }
            Ok(r) => r.map_err(|e| {
                let s = map_ftp_err(e);
                if is_conn_lost(&s) {
                    $self.healthy.store(false, Ordering::Relaxed);
                }
                s
            }),
        }
    }};
}

impl FtpFs {
    async fn abort_transfer(&self, c: &mut Client, stream: suppaftp::tokio::TransferStream<suppaftp::tokio::AsyncRustlsStream>) {
        match tokio::time::timeout(Duration::from_secs(10), c.abort(stream)).await {
            Ok(Ok(())) => {}
            _ => self.healthy.store(false, Ordering::Relaxed),
        }
    }
}

#[async_trait]
impl RemoteFs for FtpFs {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            server_side_copy: false,
            exec: false,
            hash: false,
            chmod: true, // SITE CHMOD (best effort, server may refuse)
            symlinks: true,
            utf8_names: self.utf8,
            resume: self.fl.rest,
            mlsd: self.fl.mlsd,
        }
    }

    fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    async fn ping(&self) -> Result<(), String> {
        let Ok(mut g) = self.client.try_lock() else { return Ok(()) }; // busy => alive
        let c = g.as_mut().ok_or_else(|| conn_lost("connection closed"))?;
        match tokio::time::timeout(Duration::from_secs(15), c.noop()).await {
            Err(_) => Err(conn_lost("NOOP timed out")),
            Ok(r) => r.map_err(map_ftp_err),
        }
    }

    async fn list(&self, path: &str) -> Result<Vec<RemoteEntry>, String> {
        let fl = self.fl;
        let r: Result<Vec<RemoteEntry>, String> = {
            let mut guard = self.client.lock().await;
            let c = guard.as_mut().ok_or_else(|| conn_lost("connection closed"))?;
            match tokio::time::timeout(Duration::from_secs(120), list_raw(c, path, fl)).await {
                Err(_) => Err(conn_lost("listing timed out")),
                Ok(r) => r,
            }
        };
        if let Err(e) = &r {
            if is_conn_lost(e) {
                self.healthy.store(false, Ordering::Relaxed);
            }
        }
        r
    }

    async fn stat(&self, path: &str) -> Result<RemoteEntry, String> {
        let norm = normalize_path(path);
        if norm == "/" {
            return Ok(RemoteEntry {
                name: "/".into(),
                path: "/".into(),
                kind: "dir".into(),
                size: 0,
                modified: None,
                permissions: None,
                link_target: None,
                target_is_dir: None,
            });
        }
        if self.fl.mlst {
            let r: Result<Option<RemoteEntry>, String> = op!(self, c, async {
                let line = c.mlst(Some(path)).await?;
                Ok::<_, FtpError>(ListParser::parse_mlst(&line).ok().and_then(|f| to_entry(&parent_path(path), &f)))
            });
            if let Ok(Some(mut e)) = r {
                e.path = path.to_string();
                return Ok(e);
            }
        }
        let parent = parent_path(path);
        let name = base_name(path);
        let list = self.list(&parent).await?;
        list.into_iter()
            .find(|e| e.name == name)
            .ok_or_else(|| format!("NOT_FOUND: '{path}'"))
    }

    async fn download(
        &self,
        remote: &str,
        local: &Path,
        resume: bool,
        progress: ProgressFn<'_>,
        cancel: &CancellationToken,
    ) -> Result<u64, String> {
        let fl = self.fl;
        let mut guard = self.client.lock().await;
        let c = guard.as_mut().ok_or_else(|| conn_lost("connection closed"))?;
        let size = if fl.size { c.size(remote).await.ok().map(|s| s as u64) } else { None };
        let (mut out, offset) = open_local_download(local, resume && fl.rest, size).await?;
        if offset > 0 {
            c.resume_transfer(offset as usize).await.map_err(map_ftp_err)?;
        }
        let mut stream = c.retr_as_stream(remote).await.map_err(map_ftp_err)?;
        match pump(&mut stream, &mut out, offset, progress, cancel, true).await {
            Ok(total) => {
                out.flush().await.map_err(|e| format!("local write error: {e}"))?;
                c.finish_transfer(stream).await?;
                Ok(total)
            }
            Err(e) => {
                self.abort_transfer(c, stream).await;
                if is_conn_lost(&e) {
                    self.healthy.store(false, Ordering::Relaxed);
                }
                Err(e)
            }
        }
    }

    async fn upload(
        &self,
        local: &Path,
        remote: &str,
        resume: bool,
        progress: ProgressFn<'_>,
        cancel: &CancellationToken,
    ) -> Result<u64, String> {
        let fl = self.fl;
        let mut src = tokio::fs::File::open(local).await.map_err(|e| format!("cannot open local file: {e}"))?;
        let size = src.metadata().await.map_err(|e| e.to_string())?.len();
        let mut guard = self.client.lock().await;
        let c = guard.as_mut().ok_or_else(|| conn_lost("connection closed"))?;
        let mut offset = 0u64;
        if resume && fl.rest && fl.size {
            if let Ok(rs) = c.size(remote).await {
                let rs = rs as u64;
                if rs > 0 && rs <= size {
                    offset = rs;
                }
            }
        }
        if offset > 0 {
            c.resume_transfer(offset as usize).await.map_err(map_ftp_err)?;
            src.seek(std::io::SeekFrom::Start(offset)).await.map_err(|e| e.to_string())?;
        }
        let mut stream = c.put_with_stream(remote).await.map_err(map_ftp_err)?;
        match pump(&mut src, &mut stream, offset, progress, cancel, false).await {
            Ok(total) => {
                c.finish_transfer(stream).await?;
                Ok(total)
            }
            Err(e) => {
                self.abort_transfer(c, stream).await;
                if is_conn_lost(&e) {
                    self.healthy.store(false, Ordering::Relaxed);
                }
                Err(e)
            }
        }
    }

    async fn mkdir(&self, path: &str, recursive: bool) -> Result<(), String> {
        if !recursive {
            return op!(self, c, c.mkdir(path));
        }
        let prefixes = path_prefixes(path);
        op!(self, c, async {
            for p in &prefixes {
                if c.cwd(p).await.is_ok() {
                    continue;
                }
                c.mkdir(p).await?;
            }
            Ok::<_, FtpError>(())
        })
    }

    async fn rename(&self, from: &str, to: &str) -> Result<(), String> {
        op!(self, c, c.rename(from, to))
    }

    async fn delete(&self, path: &str, recursive: bool) -> Result<(), String> {
        let fl = self.fl;
        let mut guard = self.client.lock().await;
        let c = guard.as_mut().ok_or_else(|| conn_lost("connection closed"))?;
        // A file (or symlink) goes with DELE; a directory needs RMD (after emptying it if recursive).
        if c.rm(path).await.is_ok() {
            return Ok(());
        }
        if recursive {
            delete_rec(c, path, fl).await
        } else {
            c.rmdir(path).await.map_err(map_ftp_err)
        }
    }

    async fn chmod(&self, path: &str, mode: u32) -> Result<(), String> {
        let cmd = format!("CHMOD {:o} {}", mode & 0o7777, path);
        op!(self, c, c.site(cmd)).map(|_| ())
    }

    async fn read_small_file(&self, path: &str) -> Result<Vec<u8>, String> {
        let fl = self.fl;
        let mut guard = self.client.lock().await;
        let c = guard.as_mut().ok_or_else(|| conn_lost("connection closed"))?;
        if fl.size {
            if let Ok(s) = c.size(path).await {
                if s as u64 > SMALL_FILE_LIMIT {
                    return Err(format!("TOO_LARGE: file is larger than {SMALL_FILE_LIMIT} bytes"));
                }
            }
        }
        let mut stream = c.retr_as_stream(path).await.map_err(map_ftp_err)?;
        let mut buf = Vec::new();
        let read = tokio::time::timeout(OP_TIMEOUT, (&mut stream).take(SMALL_FILE_LIMIT + 1).read_to_end(&mut buf)).await;
        match read {
            Ok(Ok(_)) if buf.len() as u64 <= SMALL_FILE_LIMIT => {
                c.finish_transfer(stream).await?;
                Ok(buf)
            }
            Ok(Ok(_)) => {
                self.abort_transfer(c, stream).await;
                Err(format!("TOO_LARGE: file is larger than {SMALL_FILE_LIMIT} bytes"))
            }
            Ok(Err(e)) => {
                self.abort_transfer(c, stream).await;
                Err(conn_lost(e))
            }
            Err(_) => {
                self.abort_transfer(c, stream).await;
                Err(conn_lost("read timed out"))
            }
        }
    }

    async fn write_small_file(&self, path: &str, data: &[u8]) -> Result<(), String> {
        if data.len() as u64 > SMALL_FILE_LIMIT {
            return Err(format!("TOO_LARGE: limit is {SMALL_FILE_LIMIT} bytes"));
        }
        let mut guard = self.client.lock().await;
        let c = guard.as_mut().ok_or_else(|| conn_lost("connection closed"))?;
        let mut stream = c.put_with_stream(path).await.map_err(map_ftp_err)?;
        match tokio::time::timeout(OP_TIMEOUT, stream.write_all(data)).await {
            Ok(Ok(())) => c.finish_transfer(stream).await,
            Ok(Err(e)) => {
                self.abort_transfer(c, stream).await;
                Err(conn_lost(e))
            }
            Err(_) => {
                self.abort_transfer(c, stream).await;
                Err(conn_lost("write timed out"))
            }
        }
    }

    async fn close(&self) {
        let mut g = self.client.lock().await;
        if let Some(mut c) = g.take() {
            let _ = tokio::time::timeout(Duration::from_secs(5), c.quit()).await;
        }
    }
}

/// Small extension so both transfer paths finish a data stream the same way.
#[async_trait]
trait FinishTransfer {
    async fn finish_transfer(
        &mut self,
        stream: suppaftp::tokio::TransferStream<suppaftp::tokio::AsyncRustlsStream>,
    ) -> Result<(), String>;
}

#[async_trait]
impl FinishTransfer for Client {
    async fn finish_transfer(
        &mut self,
        stream: suppaftp::tokio::TransferStream<suppaftp::tokio::AsyncRustlsStream>,
    ) -> Result<(), String> {
        tokio::time::timeout(OP_TIMEOUT, stream.finish())
            .await
            .map_err(|_| conn_lost("transfer completion timed out"))?
            .map_err(map_ftp_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persian_names_roundtrip_utf8() {
        let (utf8, legacy) = choose_encoding(true, None).unwrap();
        assert!(utf8);
        let enc = AutoEncoding { legacy, utf8_out: utf8 };
        let name = "گزارش ۱۴۰۳.txt";
        assert_eq!(enc.decode(&enc.encode(name).unwrap()), name);
    }

    #[test]
    fn legacy_cp1256_roundtrip_and_fallback_decode() {
        let (utf8, legacy) = choose_encoding(false, Some("windows-1256")).unwrap();
        assert!(!utf8);
        let enc = AutoEncoding { legacy, utf8_out: false };
        let bytes = enc.encode("سلام.txt").unwrap();
        assert!(std::str::from_utf8(&bytes).is_err());
        assert_eq!(enc.decode(&bytes), "سلام.txt");
        // Valid UTF-8 from the server is still decoded as UTF-8.
        assert_eq!(enc.decode("سلام".as_bytes()), "سلام");
    }

    #[test]
    fn legacy_encode_rejects_unmappable() {
        let (_, legacy) = choose_encoding(false, Some("windows-1252")).unwrap();
        let enc = AutoEncoding { legacy, utf8_out: false };
        assert!(enc.encode("سلام").is_err());
        assert!(enc.encode("café").is_ok());
    }

    #[test]
    fn encoding_choice_rules() {
        assert!(choose_encoding(false, Some("nonsense-charset")).is_err());
        assert!(choose_encoding(false, Some("utf-16le")).is_err());
        assert!(choose_encoding(false, Some("utf-8")).unwrap().0);
        assert!(!choose_encoding(false, None).unwrap().0);
    }

    #[test]
    fn list_line_parsing() {
        let f = parse_list_line("-rw-r--r-- 1 u g 1234 Jan  5 12:00 a.txt", false).unwrap();
        assert!(f.is_file() && f.size() == 1234);
        let f = parse_list_line("type=dir;modify=20201019151930;UNIX.mode=0755; pub", true).unwrap();
        assert!(f.is_directory());
        assert!(parse_list_line("", false).is_none());
        assert!(parse_list_line("total 12", false).is_none());
    }
}
