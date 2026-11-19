//! SFTP backend (russh + russh-sftp). One SSH session, one SFTP channel; concurrent transfers
//! multiplex over it (`parallel_safe() == true`).

use std::future::Future;
use std::io::SeekFrom;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use russh_sftp::client::error::Error as SftpError;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{FileAttributes, FileType, OpenFlags, StatusCode};
use tauri::AppHandle;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use super::ssh_common::{connect_ssh, exec_collect, shell_quote, SshHandle, SshProfile};
use super::*;

pub struct SftpFs {
    ssh: SshHandle,
    sftp: SftpSession,
}

fn map_err(e: SftpError) -> String {
    match e {
        SftpError::Status(s) => match s.status_code {
            StatusCode::NoSuchFile => format!("NOT_FOUND: {}", s.error_message),
            StatusCode::NoConnection | StatusCode::ConnectionLost => conn_lost(&s.error_message),
            StatusCode::PermissionDenied => format!("Permission denied: {}", s.error_message),
            c => format!("SFTP error {c}: {}", s.error_message),
        },
        SftpError::IO(m) => conn_lost(m),
        SftpError::Timeout => conn_lost("SFTP request timed out"),
        other => other.to_string(),
    }
}

pub async fn connect(app: &AppHandle, profile: &RemoteProfile) -> Result<(Arc<dyn RemoteFs>, ProtocolInfo), String> {
    let sp = SshProfile::from(profile);
    let ssh = connect_ssh(app, &sp).await?;
    let channel = ssh.channel_open_session().await.map_err(conn_lost)?;
    channel.request_subsystem(true, "sftp").await.map_err(|e| format!("SFTP subsystem unavailable: {e}"))?;
    let sftp = SftpSession::new(channel.into_stream()).await.map_err(map_err)?;
    sftp.set_timeout(60);
    let home = sftp.canonicalize(".").await.ok();
    let info = ProtocolInfo {
        protocol: "sftp".into(),
        banner: None,
        home,
        tls: true,
        encoding: Some("utf-8".into()),
        host_key_fingerprint: Some(ssh.host_key_fingerprint.clone()),
    };
    Ok((Arc::new(SftpFs { ssh, sftp }), info))
}

fn kind_of(t: FileType) -> &'static str {
    match t {
        FileType::Dir => "dir",
        FileType::File => "file",
        FileType::Symlink => "symlink",
        FileType::Other => "other",
    }
}

fn entry_from(path: &str, name: &str, m: &FileAttributes) -> RemoteEntry {
    RemoteEntry {
        name: name.to_string(),
        path: path.to_string(),
        kind: kind_of(m.file_type()).to_string(),
        size: m.size.unwrap_or(0),
        modified: m.mtime.map(|t| t as i64),
        permissions: m.permissions.map(|p| p & 0o7777),
        link_target: None,
        target_is_dir: None,
    }
}

impl SftpFs {
    fn alive(&self) -> Result<(), String> {
        if self.ssh.is_closed() {
            Err(conn_lost("SSH session closed"))
        } else {
            Ok(())
        }
    }

    async fn resolve_link(&self, e: &mut RemoteEntry) {
        if e.kind == "symlink" {
            e.link_target = self.sftp.read_link(e.path.clone()).await.ok();
            e.target_is_dir = self.sftp.metadata(e.path.clone()).await.ok().map(|m| m.file_type().is_dir());
        }
    }

    fn delete_rec<'a>(&'a self, path: &'a str) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let md = self.sftp.symlink_metadata(path.to_string()).await.map_err(map_err)?;
            if md.file_type().is_dir() {
                let entries = self.sftp.read_dir(path.to_string()).await.map_err(map_err)?;
                for ent in entries {
                    let n = ent.file_name();
                    if n == "." || n == ".." {
                        continue;
                    }
                    self.delete_rec(&join_path(path, &n)).await?;
                }
                self.sftp.remove_dir(path.to_string()).await.map_err(map_err)
            } else {
                self.sftp.remove_file(path.to_string()).await.map_err(map_err)
            }
        })
    }
}

#[async_trait]
impl RemoteFs for SftpFs {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            server_side_copy: false,
            exec: true,
            hash: true,
            chmod: true,
            symlinks: true,
            utf8_names: true,
            resume: true,
            mlsd: false,
        }
    }

    fn parallel_safe(&self) -> bool {
        true
    }

    async fn ping(&self) -> Result<(), String> {
        self.alive()?;
        tokio::time::timeout(std::time::Duration::from_secs(15), self.ssh.send_keepalive(true))
            .await
            .map_err(|_| conn_lost("keepalive timed out"))?
            .map_err(conn_lost)
    }

    async fn list(&self, path: &str) -> Result<Vec<RemoteEntry>, String> {
        self.alive()?;
        let rd = self.sftp.read_dir(path.to_string()).await.map_err(map_err)?;
        let mut out = Vec::new();
        for ent in rd {
            let name = ent.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let full = join_path(path, &name);
            let mut e = entry_from(&full, &name, &ent.metadata());
            self.resolve_link(&mut e).await;
            out.push(e);
        }
        Ok(out)
    }

    async fn stat(&self, path: &str) -> Result<RemoteEntry, String> {
        self.alive()?;
        let md = self.sftp.symlink_metadata(path.to_string()).await.map_err(map_err)?;
        let mut e = entry_from(path, &base_name(path), &md);
        self.resolve_link(&mut e).await;
        Ok(e)
    }

    async fn download(
        &self,
        remote: &str,
        local: &Path,
        resume: bool,
        progress: ProgressFn<'_>,
        cancel: &CancellationToken,
    ) -> Result<u64, String> {
        self.alive()?;
        let mut src = self.sftp.open(remote.to_string()).await.map_err(map_err)?;
        let size = src.metadata().await.ok().and_then(|m| m.size);
        let (mut out, offset) = open_local_download(local, resume, size).await?;
        if offset > 0 {
            src.seek(SeekFrom::Start(offset)).await.map_err(conn_lost)?;
        }
        let total = pump(&mut src, &mut out, offset, progress, cancel, true).await?;
        out.flush().await.map_err(|e| format!("local write error: {e}"))?;
        let _ = src.shutdown().await;
        Ok(total)
    }

    async fn upload(
        &self,
        local: &Path,
        remote: &str,
        resume: bool,
        progress: ProgressFn<'_>,
        cancel: &CancellationToken,
    ) -> Result<u64, String> {
        self.alive()?;
        let mut src = tokio::fs::File::open(local).await.map_err(|e| format!("cannot open local file: {e}"))?;
        let size = src.metadata().await.map_err(|e| e.to_string())?.len();
        let mut offset = 0u64;
        if resume {
            if let Ok(m) = self.sftp.metadata(remote.to_string()).await {
                let rs = m.size.unwrap_or(0);
                if rs > 0 && rs <= size {
                    offset = rs;
                }
            }
        }
        let mut flags = OpenFlags::WRITE | OpenFlags::CREATE;
        if offset == 0 {
            flags |= OpenFlags::TRUNCATE;
        }
        let mut dst = self.sftp.open_with_flags(remote.to_string(), flags).await.map_err(map_err)?;
        if offset > 0 {
            dst.seek(SeekFrom::Start(offset)).await.map_err(conn_lost)?;
            src.seek(SeekFrom::Start(offset)).await.map_err(|e| e.to_string())?;
        }
        let total = pump(&mut src, &mut dst, offset, progress, cancel, false).await?;
        dst.shutdown().await.map_err(conn_lost)?;
        Ok(total)
    }

    async fn mkdir(&self, path: &str, recursive: bool) -> Result<(), String> {
        self.alive()?;
        if !recursive {
            return self.sftp.create_dir(path.to_string()).await.map_err(map_err);
        }
        for p in path_prefixes(path) {
            if let Ok(m) = self.sftp.metadata(p.clone()).await {
                if m.file_type().is_dir() {
                    continue;
                }
                return Err(format!("EXISTS: '{p}' is not a directory"));
            }
            self.sftp.create_dir(p).await.map_err(map_err)?;
        }
        Ok(())
    }

    async fn rename(&self, from: &str, to: &str) -> Result<(), String> {
        self.alive()?;
        self.sftp.rename(from.to_string(), to.to_string()).await.map_err(map_err)
    }

    async fn delete(&self, path: &str, recursive: bool) -> Result<(), String> {
        self.alive()?;
        if recursive {
            return self.delete_rec(path).await;
        }
        let md = self.sftp.symlink_metadata(path.to_string()).await.map_err(map_err)?;
        if md.file_type().is_dir() {
            self.sftp.remove_dir(path.to_string()).await.map_err(map_err)
        } else {
            self.sftp.remove_file(path.to_string()).await.map_err(map_err)
        }
    }

    async fn chmod(&self, path: &str, mode: u32) -> Result<(), String> {
        self.alive()?;
        let attrs = FileAttributes { permissions: Some(mode & 0o7777), ..FileAttributes::empty() };
        self.sftp.set_metadata(path.to_string(), attrs).await.map_err(map_err)
    }

    async fn read_small_file(&self, path: &str) -> Result<Vec<u8>, String> {
        self.alive()?;
        let md = self.sftp.metadata(path.to_string()).await.map_err(map_err)?;
        if md.size.unwrap_or(0) > SMALL_FILE_LIMIT {
            return Err(format!("TOO_LARGE: file is larger than {SMALL_FILE_LIMIT} bytes"));
        }
        let data = self.sftp.read(path.to_string()).await.map_err(map_err)?;
        if data.len() as u64 > SMALL_FILE_LIMIT {
            return Err(format!("TOO_LARGE: file is larger than {SMALL_FILE_LIMIT} bytes"));
        }
        Ok(data)
    }

    async fn write_small_file(&self, path: &str, data: &[u8]) -> Result<(), String> {
        self.alive()?;
        if data.len() as u64 > SMALL_FILE_LIMIT {
            return Err(format!("TOO_LARGE: limit is {SMALL_FILE_LIMIT} bytes"));
        }
        self.sftp.write(path.to_string(), data).await.map_err(map_err)
    }

    async fn hash(&self, path: &str, algo: &str) -> Result<String, String> {
        self.alive()?;
        if algo != "sha256" {
            return Err("UNSUPPORTED: only sha256".into());
        }
        let out = exec_collect(&self.ssh, &format!("sha256sum -- {}", shell_quote(path)), 4096).await?;
        let text = String::from_utf8_lossy(&out.stdout);
        let hex = text.split_whitespace().next().unwrap_or("");
        if out.exit_status == Some(0) && hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            Ok(hex.to_lowercase())
        } else {
            Err(format!("UNSUPPORTED: sha256sum failed on server ({})", String::from_utf8_lossy(&out.stderr).trim()))
        }
    }

    async fn close(&self) {
        let _ = self.sftp.close().await;
        let _ = self.ssh.disconnect(russh::Disconnect::ByApplication, "", "en").await;
    }
}
