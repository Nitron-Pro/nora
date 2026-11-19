//! Guarded one-shot command execution over SSH (`exec_run`).
//!
//! The command is checked by [`CommandGuard`] (default policy: deny all) BEFORE any network
//! activity, and the canonical `normalized` string - never the raw input - is what runs on the
//! remote exec channel. Every verdict is audited. Optionally, authenticated SSH sessions are
//! pooled by `session_key` (idle timeout 60 s) so repeated execs do not reconnect.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine;
use russh::ChannelMsg;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use tokio_util::sync::CancellationToken;

use super::audit::{self, Source};
use super::guard::{CommandGuard, GuardPolicy, Verdict};
use crate::commands::remote::conn_lost;
use crate::commands::remote::ssh_common::{connect_ssh, SshHandle, SshProfile};

const DEFAULT_TIMEOUT_SECS: u64 = 60;
const MAX_TIMEOUT_SECS: u64 = 3600;
const DEFAULT_MAX_OUTPUT: u64 = 4 * 1024 * 1024;
const MAX_MAX_OUTPUT: u64 = 64 * 1024 * 1024;
const MAX_CONCURRENT_EXECS: usize = 16;
const EVENT_CHUNK: usize = 32 * 1024;
const POOL_IDLE: Duration = Duration::from_secs(60);
const MAX_POOL: usize = 8;

#[derive(Debug, Deserialize)]
pub struct ExecRequest {
    pub profile: SshProfile,
    pub command: String,
    #[serde(default)]
    pub policy: Option<GuardPolicy>,
    #[serde(default, alias = "timeoutSecs")]
    pub timeout_secs: Option<u64>,
    #[serde(default, alias = "maxOutputBytes")]
    pub max_output_bytes: Option<u64>,
    #[serde(default, alias = "userLabel")]
    pub user_label: Option<String>,
    /// Reuse (and keep for 60 s) an authenticated session under this key.
    #[serde(default, alias = "sessionKey")]
    pub session_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExecRunResult {
    pub exec_id: String,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn running() -> &'static Mutex<HashMap<String, CancellationToken>> {
    static R: OnceLock<Mutex<HashMap<String, CancellationToken>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(HashMap::new()))
}

// ---------------------------------------------------------------------------------------------
// Session pool
// ---------------------------------------------------------------------------------------------

struct PoolEntry {
    sig: String,
    handle: Arc<SshHandle>,
    last_used: Instant,
}

fn pool() -> &'static Mutex<HashMap<String, PoolEntry>> {
    static P: OnceLock<Mutex<HashMap<String, PoolEntry>>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Identity of a profile for pool matching (no secrets, only refs).
fn profile_sig(p: &SshProfile) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}",
        p.host.trim().to_lowercase(),
        p.port,
        p.username,
        p.auth.as_deref().unwrap_or("password"),
        p.secret_ref.as_deref().unwrap_or(""),
        p.passphrase_ref.as_deref().unwrap_or("")
    )
}

fn pool_get(key: &str, sig: &str) -> Option<Arc<SshHandle>> {
    let mut p = lock(pool());
    match p.get_mut(key) {
        Some(e) if e.sig == sig && !e.handle.is_closed() => {
            e.last_used = Instant::now();
            Some(e.handle.clone())
        }
        Some(_) => {
            p.remove(key);
            None
        }
        None => None,
    }
}

fn pool_put(key: &str, sig: String, handle: Arc<SshHandle>) {
    let mut p = lock(pool());
    if p.len() >= MAX_POOL && !p.contains_key(key) {
        // Evict the least recently used entry.
        if let Some(old) = p.iter().min_by_key(|(_, e)| e.last_used).map(|(k, _)| k.clone()) {
            p.remove(&old);
        }
    }
    p.insert(key.to_string(), PoolEntry { sig, handle, last_used: Instant::now() });
    drop(p);
    ensure_sweeper();
}

fn ensure_sweeper() {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        tauri::async_runtime::spawn(async {
            let mut iv = tokio::time::interval(Duration::from_secs(15));
            loop {
                iv.tick().await;
                let mut p = lock(pool());
                p.retain(|_, e| e.last_used.elapsed() < POOL_IDLE && !e.handle.is_closed());
            }
        });
    });
}

async fn acquire(app: &AppHandle, profile: &SshProfile, key: Option<&str>) -> Result<(Arc<SshHandle>, bool), String> {
    let sig = profile_sig(profile);
    if let Some(k) = key {
        if let Some(h) = pool_get(k, &sig) {
            return Ok((h, true));
        }
    }
    let h = Arc::new(connect_ssh(app, profile).await?);
    if let Some(k) = key {
        pool_put(k, sig, h.clone());
    }
    Ok((h, false))
}

// ---------------------------------------------------------------------------------------------
// exec_run
// ---------------------------------------------------------------------------------------------

#[tauri::command]
pub async fn exec_run(app: AppHandle, req: ExecRequest) -> Result<ExecRunResult, String> {
    let guard = CommandGuard::new(&req.policy.clone().unwrap_or_default())?;
    let exec_id = format!("exec-{}", uuid::Uuid::new_v4().simple());
    let label = req.user_label.clone().unwrap_or_default();
    let conn_id = req
        .session_key
        .clone()
        .unwrap_or_else(|| format!("exec:{}:{}", req.profile.host.trim(), req.profile.port));

    let verdict = guard.check(&req.command);
    audit::record_verdict(&conn_id, &label, Source::Exec, &req.command, &verdict);
    let normalized = match verdict {
        Verdict::Allow { normalized } => normalized,
        Verdict::Deny { reason_code, message } => return Err(format!("DENIED:{reason_code}:{message}")),
    };

    let cancel = CancellationToken::new();
    {
        let mut r = lock(running());
        if r.len() >= MAX_CONCURRENT_EXECS {
            return Err(format!("LIMIT: at most {MAX_CONCURRENT_EXECS} concurrent executions"));
        }
        r.insert(exec_id.clone(), cancel.clone());
    }

    let timeout = Duration::from_secs(req.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS).clamp(1, MAX_TIMEOUT_SECS));
    let max_out = req.max_output_bytes.unwrap_or(DEFAULT_MAX_OUTPUT).clamp(1, MAX_MAX_OUTPUT);
    let id = exec_id.clone();
    tauri::async_runtime::spawn(async move {
        let res = run_one(&app, &id, &req.profile, req.session_key.as_deref(), &normalized, timeout, max_out, &cancel).await;
        lock(running()).remove(&id);
        let _ = app.emit(
            "terminal://exec-done",
            serde_json::json!({
                "exec_id": id,
                "exit_status": res.exit_status,
                "timed_out": res.timed_out,
                "truncated": res.truncated,
                "error": res.error,
            }),
        );
    });
    Ok(ExecRunResult { exec_id })
}

#[derive(Default)]
struct RunResult {
    exit_status: Option<u32>,
    timed_out: bool,
    truncated: bool,
    error: Option<String>,
}

fn emit_exec(app: &AppHandle, id: &str, stream: &str, data: &[u8]) {
    for chunk in data.chunks(EVENT_CHUNK) {
        let b64 = base64::engine::general_purpose::STANDARD.encode(chunk);
        let _ = app.emit(
            "terminal://exec-data",
            serde_json::json!({ "exec_id": id, "stream": stream, "data_b64": b64 }),
        );
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_one(
    app: &AppHandle,
    id: &str,
    profile: &SshProfile,
    key: Option<&str>,
    command: &str,
    timeout: Duration,
    max_out: u64,
    cancel: &CancellationToken,
) -> RunResult {
    let mut res = RunResult::default();

    // Connect (or reuse), then open a channel; a stale pooled session is replaced once.
    let mut attempt = 0;
    let (handle, mut channel) = loop {
        let acquired = tokio::select! {
            _ = cancel.cancelled() => { res.error = Some("cancelled".into()); return res; }
            r = acquire(app, profile, key) => r,
        };
        let (h, reused) = match acquired {
            Ok(v) => v,
            Err(e) => {
                res.error = Some(e);
                return res;
            }
        };
        match h.channel_open_session().await {
            Ok(c) => break (h, c),
            Err(e) => {
                if let Some(k) = key {
                    lock(pool()).remove(k);
                }
                if reused && attempt == 0 {
                    attempt += 1;
                    continue;
                }
                res.error = Some(conn_lost(e));
                return res;
            }
        }
    };

    if let Err(e) = channel.exec(true, command.as_bytes().to_vec()).await {
        res.error = Some(conn_lost(e));
        finish_handle(&handle, key).await;
        return res;
    }

    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    let mut total: u64 = 0;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => { res.error = Some("cancelled".into()); let _ = channel.close().await; break; }
            _ = &mut deadline => { res.timed_out = true; let _ = channel.close().await; break; }
            msg = channel.wait() => {
                let Some(msg) = msg else { break };
                match msg {
                    ChannelMsg::Data { data } => {
                        if forward(app, id, "stdout", &data, &mut total, max_out, &mut res) { let _ = channel.close().await; break; }
                    }
                    ChannelMsg::ExtendedData { data, .. } => {
                        if forward(app, id, "stderr", &data, &mut total, max_out, &mut res) { let _ = channel.close().await; break; }
                    }
                    ChannelMsg::ExitStatus { exit_status } => res.exit_status = Some(exit_status),
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
        }
    }
    finish_handle(&handle, key).await;
    res
}

/// Emit as much of `data` as the output cap allows; returns true when the cap was hit.
fn forward(app: &AppHandle, id: &str, stream: &str, data: &[u8], total: &mut u64, max: u64, res: &mut RunResult) -> bool {
    let (take, hit) = cap_output(total, max, data.len());
    if take > 0 {
        emit_exec(app, id, stream, &data[..take]);
    }
    if hit {
        res.truncated = true;
    }
    hit
}

async fn finish_handle(handle: &Arc<SshHandle>, key: Option<&str>) {
    if key.is_none() && Arc::strong_count(handle) == 1 {
        let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "en").await;
    }
}

#[tauri::command]
pub async fn exec_cancel(exec_id: String) -> Result<(), String> {
    if let Some(t) = lock(running()).get(&exec_id) {
        t.cancel();
    }
    Ok(())
}

/// Cancel all running execs and drop pooled sessions (call on app exit).
pub fn cleanup_execs() {
    for t in lock(running()).values() {
        t.cancel();
    }
    lock(pool()).clear();
}

/// Applies the output cap; returns (bytes that may be emitted, cap exceeded).
pub fn cap_output(total: &mut u64, max: u64, len: usize) -> (usize, bool) {
    let remaining = max.saturating_sub(*total);
    let take = (len as u64).min(remaining) as usize;
    *total += take as u64;
    (take, take < len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_output_limits() {
        let mut t = 0;
        assert_eq!(cap_output(&mut t, 10, 6), (6, false));
        assert_eq!(cap_output(&mut t, 10, 6), (4, true));
        assert_eq!(cap_output(&mut t, 10, 1), (0, true));
    }

    #[test]
    fn sig_ignores_case_and_has_no_secret() {
        let p = SshProfile {
            host: " Host.COM ".into(),
            port: 22,
            username: "u".into(),
            auth: None,
            secret_ref: Some("ref1".into()),
            passphrase_ref: None,
            connect_timeout_secs: None,
            keepalive_secs: None,
        };
        assert!(profile_sig(&p).starts_with("host.com|22|u|password|ref1"));
    }
}
