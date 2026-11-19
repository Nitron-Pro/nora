//! Restricted interactive SSH terminal (PTY + shell on a russh channel).
//!
//! Security model: the frontend never writes to the channel directly. `terminal_write` feeds the
//! keystrokes through [`LineTracker`] (which consults [`CommandGuard`]) and only the resulting
//! `InputAction::Forward` bytes reach the remote shell. Input is dropped until the unique prompt
//! marker has been seen (fail-closed), and after every allowed Enter until the marker returns.
//!
//! Prompt marker: after the shell starts we send one setup line that sets `PS1` (bash) / `PS1`
//! (zsh) to a prompt beginning with an invisible OSC sequence `ESC ] 777 ; nora-<token> BEL`
//! (token is random per session). The output pipe strips this sequence (also across chunk
//! boundaries) and calls `LineTracker::prompt_ready()` for each occurrence. Output before the
//! first marker is held back so the echo of the setup line can be removed. If no marker appears
//! within [`SETUP_TIMEOUT`] the session is closed (unsupported shell).
//!
//! Residual risk: the token lives in the remote `PS1` variable; a policy that allows `set`,
//! `env`, `echo $PS1` and the like would reveal it. Such rules should not be written.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use russh::ChannelMsg;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::audit::{self, AuditVerdict, Source};
use super::guard::{CommandGuard, GuardPolicy, InputAction, LineTracker, Verdict};
use crate::commands::remote::ssh_common::{connect_ssh, SshProfile};

pub const MAX_TERMINALS: usize = 8;
const SETUP_TIMEOUT: Duration = Duration::from_secs(15);
const BATCH_INTERVAL: Duration = Duration::from_millis(16);
const BATCH_MAX_BYTES: usize = 64 * 1024;
const SETUP_HOLD_MAX: usize = 256 * 1024;
const MAX_WRITE_BYTES: usize = 256 * 1024;
const NOTICE_MIN_GAP_MS: u64 = 500;

// ---------------------------------------------------------------------------------------------
// Pure helpers: marker filtering, setup echo removal, batching
// ---------------------------------------------------------------------------------------------

/// Build the invisible prompt marker bytes for a token.
pub fn marker_bytes(token: &str) -> Vec<u8> {
    format!("\x1b]777;nora-{token}\x07").into_bytes()
}

/// The single line written to the shell to install the marker prompt (bash and zsh).
/// Starts with a space so shells with `HISTCONTROL=ignorespace` keep it out of history.
pub fn setup_line(token: &str) -> String {
    format!(
        " if [ -n \"$BASH_VERSION\" ]; then unset PROMPT_COMMAND; PS1='\\[\\e]777;nora-{t}\\a\\]\\u@\\h:\\w\\$ '; \
         elif [ -n \"$ZSH_VERSION\" ]; then PS1=$'%{{\\e]777;nora-{t}\\a%}}%n@%m:%~%# '; fi\r",
        t = token
    )
}

/// Needle that begins the echoed setup line (used to cut the echo out of the held-back output).
const SETUP_NEEDLE: &[u8] = b"if [ -n \"$BASH_VERSION\"";

/// Removes the (possibly wrapped) echo of the setup line from output held before the first marker.
/// Everything from the start of the line containing the needle to the end of the held data is
/// dropped; if the needle is not found the data is returned unchanged.
pub fn hide_setup_echo(pre: &[u8]) -> Vec<u8> {
    let pos = pre
        .windows(SETUP_NEEDLE.len())
        .position(|w| w == SETUP_NEEDLE);
    match pos {
        None => pre.to_vec(),
        Some(p) => {
            // Also drop the original prompt that precedes the echo on the same line.
            let line_start = pre[..p].iter().rposition(|&b| b == b'\n').map(|i| i + 1).unwrap_or(0);
            pre[..line_start].to_vec()
        }
    }
}

/// Streaming marker stripper. Handles a marker split across any number of chunks.
pub struct MarkerFilter {
    pat: Vec<u8>,
    carry: Vec<u8>,
}

impl MarkerFilter {
    pub fn new(pat: Vec<u8>) -> Self {
        MarkerFilter { pat, carry: Vec::new() }
    }

    /// Returns (bytes without markers, number of markers removed). A trailing partial marker
    /// prefix is held back until more data arrives (or [`MarkerFilter::take_carry`]).
    pub fn push(&mut self, chunk: &[u8]) -> (Vec<u8>, usize) {
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(chunk);
        let mut out = Vec::with_capacity(buf.len());
        let mut count = 0;
        let mut i = 0;
        while i < buf.len() {
            if buf[i] == self.pat[0] {
                let rest = &buf[i..];
                if rest.starts_with(&self.pat) {
                    count += 1;
                    i += self.pat.len();
                    continue;
                }
                if self.pat.starts_with(rest) {
                    self.carry = rest.to_vec();
                    break;
                }
            }
            out.push(buf[i]);
            i += 1;
        }
        (out, count)
    }

    pub fn has_carry(&self) -> bool {
        !self.carry.is_empty()
    }

    /// Release held-back bytes (they turned out not to be a marker because time passed).
    pub fn take_carry(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.carry)
    }
}

/// Output pipe = setup hold-back + marker filter.
pub struct OutputPipe {
    filter: MarkerFilter,
    held: Option<Vec<u8>>, // Some while waiting for the first marker
}

pub struct PipeOut {
    pub data: Vec<u8>,
    pub markers: usize,
}

impl OutputPipe {
    pub fn new(marker: Vec<u8>) -> Self {
        OutputPipe { filter: MarkerFilter::new(marker), held: Some(Vec::new()) }
    }

    pub fn in_setup(&self) -> bool {
        self.held.is_some()
    }

    pub fn push(&mut self, chunk: &[u8]) -> PipeOut {
        let (clean, markers) = self.filter.push(chunk);
        match self.held.take() {
            None => PipeOut { data: clean, markers },
            Some(mut held) => {
                held.extend_from_slice(&clean);
                if markers > 0 {
                    PipeOut { data: hide_setup_echo(&held), markers }
                } else if held.len() > SETUP_HOLD_MAX {
                    // Never grow unbounded; give up hiding and show what we have.
                    PipeOut { data: held, markers: 0 }
                } else {
                    self.held = Some(held);
                    PipeOut { data: Vec::new(), markers: 0 }
                }
            }
        }
    }

    /// Output held while waiting for the first marker (used to show the cause on setup failure).
    pub fn take_held(&mut self) -> Vec<u8> {
        self.held.take().unwrap_or_default()
    }

    pub fn flush_carry(&mut self) -> Vec<u8> {
        let c = self.filter.take_carry();
        match self.held.as_mut() {
            Some(h) => {
                h.extend_from_slice(&c);
                Vec::new()
            }
            None => c,
        }
    }

    pub fn has_carry(&self) -> bool {
        self.filter.has_carry()
    }
}

/// Accumulates output and releases it in bounded batches.
#[derive(Default)]
pub struct Batcher {
    buf: Vec<u8>,
}

impl Batcher {
    /// Add data; returns a full batch if the size limit was reached.
    pub fn push(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        self.buf.extend_from_slice(data);
        if self.buf.len() >= BATCH_MAX_BYTES {
            Some(std::mem::take(&mut self.buf))
        } else {
            None
        }
    }

    pub fn take(&mut self) -> Option<Vec<u8>> {
        if self.buf.is_empty() {
            None
        } else {
            Some(std::mem::take(&mut self.buf))
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Pure input handling
// ---------------------------------------------------------------------------------------------

/// A side effect decided by [`plan_input`].
#[derive(Debug, Clone, PartialEq)]
pub enum Effect {
    /// Bytes for the remote channel.
    Send(Vec<u8>),
    /// Audit a guard verdict (Allow / Deny).
    AuditVerdict { line: String, verdict: Verdict },
    /// Audit swallowed input.
    AuditBlocked { line: String, code: String },
    /// Emit `terminal://denied`.
    Denied { line: String, reason_code: String, message: String },
    /// Local text for the UI only (never sent to the remote).
    Notice(String),
    /// An allowed command was submitted (state -> running).
    Started,
}

fn blocked_text(what: &str) -> &'static str {
    match what {
        "tab" => "Tab completion is disabled",
        "control" => "control key is disabled",
        "escape" => "escape sequence is disabled",
        "busy" => "a command is still running",
        "line_too_long" => "line too long",
        "non_ascii" => "non-ASCII input is not allowed",
        _ => "input blocked",
    }
}

fn notice_line(text: &str) -> String {
    format!("\r\n\x1b[31m[blocked by Nora policy: {}]\x1b[0m\r\n", text.replace(['\r', '\n', '\x1b'], " "))
}

/// Turn tracker actions into effects. `last_notice_ms` rate-limits notices/audit of plain
/// blocked keystrokes (so holding a key does not flood the log).
pub fn plan_input(actions: Vec<InputAction>, now_ms: u64, last_notice_ms: &mut Option<u64>) -> Vec<Effect> {
    let mut out: Vec<Effect> = Vec::new();
    for a in actions {
        match a {
            InputAction::Forward(b) => {
                if let Some(Effect::Send(prev)) = out.last_mut() {
                    prev.extend_from_slice(&b);
                } else {
                    out.push(Effect::Send(b));
                }
            }
            InputAction::LineAllowed { line, normalized } => {
                out.push(Effect::AuditVerdict { line, verdict: Verdict::Allow { normalized } });
                out.push(Effect::Started);
            }
            InputAction::LineDenied { line, reason_code, message } => {
                out.push(Effect::AuditVerdict {
                    line: line.clone(),
                    verdict: Verdict::Deny { reason_code, message: message.clone() },
                });
                out.push(Effect::Denied { line, reason_code: reason_code.to_string(), message: message.clone() });
                out.push(Effect::Notice(notice_line(&format!("{message} ({reason_code})"))));
                // The tracker already sent Ctrl-U (remote line is empty); an empty Enter gives a fresh prompt.
                out.push(Effect::Send(vec![0x0d]));
            }
            InputAction::PasteRejected { reason } => {
                out.push(Effect::AuditBlocked { line: "<paste>".into(), code: format!("paste_{reason}") });
                out.push(Effect::Notice(notice_line(&format!("paste rejected ({reason})"))));
            }
            InputAction::Blocked { what } => {
                if what == "empty" {
                    continue;
                }
                let limited = matches!(*last_notice_ms, Some(t) if now_ms.saturating_sub(t) < NOTICE_MIN_GAP_MS);
                if limited {
                    continue;
                }
                *last_notice_ms = Some(now_ms);
                out.push(Effect::AuditBlocked { line: format!("<{what}>"), code: format!("key_{what}") });
                if what != "busy" {
                    out.push(Effect::Notice(notice_line(blocked_text(what))));
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------------------------

enum Cmd {
    Data(Vec<u8>),
    Resize(u32, u32),
    Notice(Vec<u8>),
    Close,
}

struct Term {
    tx: mpsc::Sender<Cmd>,
    tracker: Mutex<LineTracker>,
    /// Serialises feed+send so concurrent writes keep their order.
    input_order: tokio::sync::Mutex<()>,
    ready: AtomicBool,
    state: Mutex<String>,
    last_input: Mutex<Instant>,
    last_notice_ms: Mutex<Option<u64>>,
    cancel: CancellationToken,
    started: Instant,
    label: String,
    host: String,
    port: u16,
    username: String,
    size: Mutex<(u32, u32)>,
    created_unix: u64,
}

fn registry() -> &'static Mutex<HashMap<String, Arc<Term>>> {
    static R: std::sync::OnceLock<Mutex<HashMap<String, Arc<Term>>>> = std::sync::OnceLock::new();
    R.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn get_term(id: &str) -> Result<Arc<Term>, String> {
    lock(registry()).get(id).cloned().ok_or_else(|| "NOT_FOUND: no such terminal".to_string())
}

fn set_state(app: &AppHandle, t: &Term, id: &str, st: &str) {
    {
        let mut s = lock(&t.state);
        if *s == st || *s == "closed" {
            return;
        }
        *s = st.to_string();
    }
    let _ = app.emit("terminal://state", serde_json::json!({ "term_id": id, "state": st }));
}

fn emit_data(app: &AppHandle, id: &str, data: &[u8]) {
    for chunk in data.chunks(BATCH_MAX_BYTES) {
        let b64 = base64::engine::general_purpose::STANDARD.encode(chunk);
        let _ = app.emit("terminal://data", serde_json::json!({ "term_id": id, "data_b64": b64 }));
    }
}

// ---------------------------------------------------------------------------------------------
// IPC
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct TerminalOpenRequest {
    pub profile: SshProfile,
    #[serde(default)]
    pub policy: Option<GuardPolicy>,
    #[serde(default = "d_cols")]
    pub cols: u32,
    #[serde(default = "d_rows")]
    pub rows: u32,
    #[serde(default, alias = "userLabel")]
    pub user_label: Option<String>,
    /// Close the session after this many seconds without user input (None/0 = never).
    #[serde(default, alias = "idleTimeoutSecs")]
    pub idle_timeout_secs: Option<u64>,
}
fn d_cols() -> u32 {
    80
}
fn d_rows() -> u32 {
    24
}

#[derive(Debug, Serialize)]
pub struct TerminalOpenResult {
    pub term_id: String,
}

#[derive(Debug, Serialize)]
pub struct TerminalInfo {
    pub term_id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub user_label: String,
    pub state: String,
    pub cols: u32,
    pub rows: u32,
    pub created_unix: u64,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn clamp_size(cols: u32, rows: u32) -> (u32, u32) {
    (cols.clamp(10, 500), rows.clamp(2, 200))
}

#[tauri::command]
pub async fn terminal_open(app: AppHandle, req: TerminalOpenRequest) -> Result<TerminalOpenResult, String> {
    let guard = Arc::new(CommandGuard::new(&req.policy.clone().unwrap_or_default())?);
    let (cols, rows) = clamp_size(req.cols, req.rows);
    let term_id = format!("term-{}", uuid::Uuid::new_v4().simple());
    let label = req.user_label.clone().unwrap_or_default();

    // Reserve a slot first so concurrent opens cannot exceed the cap.
    let (tx, rx) = mpsc::channel::<Cmd>(256);
    let term = Arc::new(Term {
        tx,
        tracker: Mutex::new(LineTracker::new(guard)),
        input_order: tokio::sync::Mutex::new(()),
        ready: AtomicBool::new(false),
        state: Mutex::new("starting".into()),
        last_input: Mutex::new(Instant::now()),
        last_notice_ms: Mutex::new(None),
        cancel: CancellationToken::new(),
        started: Instant::now(),
        label: label.clone(),
        host: req.profile.host.trim().to_string(),
        port: req.profile.port,
        username: req.profile.username.clone(),
        size: Mutex::new((cols, rows)),
        created_unix: unix_now(),
    });
    {
        let mut reg = lock(registry());
        if reg.len() >= MAX_TERMINALS {
            return Err(format!("LIMIT: at most {MAX_TERMINALS} terminals can be open"));
        }
        reg.insert(term_id.clone(), term.clone());
    }

    // Connect + PTY + shell + marker setup. Any failure releases the slot.
    let setup = async {
        let ssh = connect_ssh(&app, &req.profile).await?;
        let mut ch = ssh.channel_open_session().await.map_err(crate::commands::remote::conn_lost)?;
        ch.request_pty(true, "xterm-256color", cols, rows, 0, 0, &[])
            .await
            .map_err(crate::commands::remote::conn_lost)?;
        ch.request_shell(true).await.map_err(crate::commands::remote::conn_lost)?;
        let token = hex::encode(rand::random::<[u8; 16]>());
        ch.data(setup_line(&token).as_bytes())
            .await
            .map_err(crate::commands::remote::conn_lost)?;
        Ok::<_, String>((ssh, ch, token))
    };
    let (ssh, ch, token) = match setup.await {
        Ok(v) => v,
        Err(e) => {
            lock(registry()).remove(&term_id);
            return Err(e);
        }
    };

    let idle = req.idle_timeout_secs.filter(|s| *s > 0).map(Duration::from_secs);
    let app2 = app.clone();
    let id2 = term_id.clone();
    let t2 = term.clone();
    tauri::async_runtime::spawn(async move {
        io_loop(app2, id2, t2, ssh, ch, rx, token, idle).await;
    });
    set_state(&app, &term, &term_id, "starting");
    Ok(TerminalOpenResult { term_id })
}

#[allow(clippy::too_many_arguments)]
async fn io_loop(
    app: AppHandle,
    id: String,
    term: Arc<Term>,
    ssh: crate::commands::remote::ssh_common::SshHandle,
    mut ch: russh::Channel<russh::client::Msg>,
    mut rx: mpsc::Receiver<Cmd>,
    token: String,
    idle: Option<Duration>,
) {
    let mut pipe = OutputPipe::new(marker_bytes(&token));
    let mut batch = Batcher::default();
    let mut tick = tokio::time::interval(BATCH_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut exit_code: Option<u32> = None;
    let mut err: Option<String> = None;
    let mut got_data_since_tick = false;
    let setup_deadline = tokio::time::sleep(SETUP_TIMEOUT);
    tokio::pin!(setup_deadline);

    loop {
        tokio::select! {
            _ = term.cancel.cancelled() => { let _ = ch.close().await; break; }
            _ = &mut setup_deadline, if !term.ready.load(Ordering::SeqCst) => {
                err = Some("terminal setup timed out (shell did not accept the prompt marker; only bash/zsh are supported)".into());
                let held = pipe.take_held();
                if !held.is_empty() { emit_data(&app, &id, &held); }
                let _ = ch.close().await;
                break;
            }
            msg = ch.wait() => {
                let Some(msg) = msg else { break };
                match msg {
                    ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                        got_data_since_tick = true;
                        let out = pipe.push(&data);
                        if out.markers > 0 {
                            lock(&term.tracker).prompt_ready();
                            term.ready.store(true, Ordering::SeqCst);
                            set_state(&app, &term, &id, "ready");
                        }
                        if !out.data.is_empty() {
                            if let Some(full) = batch.push(&out.data) { emit_data(&app, &id, &full); }
                        }
                    }
                    ChannelMsg::ExitStatus { exit_status } => exit_code = Some(exit_status),
                    ChannelMsg::Failure => { err = Some("remote refused PTY/shell request".into()); break; }
                    ChannelMsg::Close | ChannelMsg::Eof => { if matches!(msg, ChannelMsg::Close) { break; } }
                    _ => {}
                }
            }
            cmd = rx.recv() => {
                match cmd {
                    None | Some(Cmd::Close) => { let _ = ch.close().await; break; }
                    Some(Cmd::Data(b)) => {
                        if ch.data(&b[..]).await.is_err() { err = Some("connection lost".into()); break; }
                    }
                    Some(Cmd::Resize(c, r)) => { let _ = ch.window_change(c, r, 0, 0).await; }
                    Some(Cmd::Notice(b)) => { if let Some(full) = batch.push(&b) { emit_data(&app, &id, &full); } }
                }
            }
            _ = tick.tick() => {
                if let Some(b) = batch.take() { emit_data(&app, &id, &b); }
                if !got_data_since_tick && pipe.has_carry() {
                    let c = pipe.flush_carry();
                    if !c.is_empty() { emit_data(&app, &id, &c); }
                }
                got_data_since_tick = false;
                if let Some(limit) = idle {
                    if lock(&term.last_input).elapsed() >= limit {
                        err = Some("idle timeout".into());
                        let _ = ch.close().await;
                        break;
                    }
                }
            }
        }
    }

    if let Some(b) = batch.take() {
        emit_data(&app, &id, &b);
    }
    if let Some(e) = &err {
        emit_data(&app, &id, notice_line(e).as_bytes());
        set_state(&app, &term, &id, "error");
    }
    // Mark closed (bypasses set_state's closed guard ordering).
    *lock(&term.state) = "closed".into();
    lock(registry()).remove(&id);
    let _ = app.emit("terminal://state", serde_json::json!({ "term_id": id, "state": "closed" }));
    let _ = app.emit("terminal://exit", serde_json::json!({ "term_id": id, "code": exit_code }));
    let _ = ssh.disconnect(russh::Disconnect::ByApplication, "", "en").await;
    let _ = term.started; // keep field used for diagnostics
}

#[tauri::command]
pub async fn terminal_write(app: AppHandle, term_id: String, data: String) -> Result<(), String> {
    if data.len() > MAX_WRITE_BYTES {
        return Err("INVALID: input too large".into());
    }
    let term = get_term(&term_id)?;
    // Fail-closed: nothing reaches the shell before the marker prompt is confirmed.
    if !term.ready.load(Ordering::SeqCst) {
        return Ok(());
    }
    let _order = term.input_order.lock().await;
    *lock(&term.last_input) = Instant::now();
    let actions = lock(&term.tracker).feed(data.as_bytes());
    let now_ms = term.started.elapsed().as_millis() as u64;
    let effects = {
        let mut last = lock(&term.last_notice_ms);
        plan_input(actions, now_ms, &mut last)
    };
    for e in effects {
        match e {
            Effect::Send(b) => term.tx.send(Cmd::Data(b)).await.map_err(|_| "CLOSED: terminal closed".to_string())?,
            Effect::AuditVerdict { line, verdict } => {
                audit::record_verdict(&term_id, &term.label, Source::Pty, &line, &verdict)
            }
            Effect::AuditBlocked { line, code } => {
                audit::record(&term_id, &term.label, Source::Pty, &line, AuditVerdict::Blocked, Some(&code))
            }
            Effect::Denied { line, reason_code, message } => {
                let _ = app.emit(
                    "terminal://denied",
                    serde_json::json!({ "term_id": term_id, "line": audit::redact(&line), "reason_code": reason_code, "message": message }),
                );
            }
            Effect::Notice(s) => {
                let _ = term.tx.send(Cmd::Notice(s.into_bytes())).await;
            }
            Effect::Started => set_state(&app, &term, &term_id, "running"),
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn terminal_resize(term_id: String, cols: u32, rows: u32) -> Result<(), String> {
    let term = get_term(&term_id)?;
    let (c, r) = clamp_size(cols, rows);
    *lock(&term.size) = (c, r);
    term.tx.send(Cmd::Resize(c, r)).await.map_err(|_| "CLOSED: terminal closed".to_string())
}

#[tauri::command]
pub async fn terminal_close(term_id: String) -> Result<(), String> {
    let term = match get_term(&term_id) {
        Ok(t) => t,
        Err(_) => return Ok(()),
    };
    let _ = term.tx.try_send(Cmd::Close);
    term.cancel.cancel();
    Ok(())
}

/// Replace the policy of an open session (the connection and shell stay open).
/// Note: the tracker state is rebuilt, so a command that is currently running is no longer gated.
#[tauri::command]
pub async fn terminal_set_policy(term_id: String, policy: Option<GuardPolicy>) -> Result<(), String> {
    let term = get_term(&term_id)?;
    let guard = Arc::new(CommandGuard::new(&policy.unwrap_or_default())?);
    let _order = term.input_order.lock().await;
    *lock(&term.tracker) = LineTracker::new(guard);
    Ok(())
}

#[tauri::command]
pub async fn terminal_list() -> Result<Vec<TerminalInfo>, String> {
    let reg = lock(registry());
    let mut v: Vec<TerminalInfo> = reg
        .iter()
        .map(|(id, t)| {
            let (cols, rows) = *lock(&t.size);
            TerminalInfo {
                term_id: id.clone(),
                host: t.host.clone(),
                port: t.port,
                username: t.username.clone(),
                user_label: t.label.clone(),
                state: lock(&t.state).clone(),
                cols,
                rows,
                created_unix: t.created_unix,
            }
        })
        .collect();
    v.sort_by_key(|i| i.created_unix);
    Ok(v)
}

/// Close every terminal (call on app exit).
pub fn cleanup_terminals() {
    let all: Vec<Arc<Term>> = lock(registry()).values().cloned().collect();
    for t in all {
        let _ = t.tx.try_send(Cmd::Close);
        t.cancel.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_filter(chunks: &[&[u8]], marker: &[u8]) -> (Vec<u8>, usize) {
        let mut f = MarkerFilter::new(marker.to_vec());
        let (mut out, mut n) = (Vec::new(), 0);
        for c in chunks {
            let (o, k) = f.push(c);
            out.extend(o);
            n += k;
        }
        (out, n)
    }

    #[test]
    fn marker_whole_and_split() {
        let m = marker_bytes("abc");
        let (o, n) = run_filter(&[b"hi\x1b]777;nora-abc\x07$ "], &m);
        assert_eq!((o.as_slice(), n), (&b"hi$ "[..], 1));
        // split at every possible boundary
        let full = [b"x".as_slice(), &m, b"y"].concat();
        for cut in 0..=full.len() {
            let (o, n) = run_filter(&[&full[..cut], &full[cut..]], &m);
            assert_eq!(o, b"xy", "cut {cut}");
            assert_eq!(n, 1, "cut {cut}");
        }
        // byte by byte
        let chunks: Vec<&[u8]> = full.chunks(1).collect();
        let (o, n) = run_filter(&chunks, &m);
        assert_eq!((o.as_slice(), n), (&b"xy"[..], 1));
    }

    #[test]
    fn partial_prefix_not_marker_is_released() {
        let m = marker_bytes("abc");
        let mut f = MarkerFilter::new(m.clone());
        let (o, n) = f.push(b"a\x1b]77");
        assert_eq!((o.as_slice(), n), (&b"a"[..], 0));
        assert!(f.has_carry());
        let (o, _) = f.push(b"X");
        assert_eq!(o, b"\x1b]77X");
        let (_, _) = f.push(b"\x1b");
        assert_eq!(f.take_carry(), b"\x1b");
    }

    #[test]
    fn multiple_markers() {
        let m = marker_bytes("t");
        let data = [m.clone(), b"a".to_vec(), m.clone()].concat();
        let (o, n) = run_filter(&[&data], &m);
        assert_eq!((o.as_slice(), n), (&b"a"[..], 2));
    }

    #[test]
    fn setup_echo_removed() {
        let m = marker_bytes("tok");
        let mut p = OutputPipe::new(m.clone());
        let line = setup_line("tok");
        let o1 = p.push(b"Welcome\r\nuser@h:~$ ");
        assert!(o1.data.is_empty() && o1.markers == 0);
        let o2 = p.push(line.as_bytes());
        assert!(o2.data.is_empty());
        let mut tail = b"\r\n".to_vec();
        tail.extend_from_slice(&m);
        tail.extend_from_slice(b"user@h:~$ ");
        let o3 = p.push(&tail);
        assert_eq!(o3.markers, 1);
        assert_eq!(o3.data, b"Welcome\r\n");
        assert!(!p.in_setup());
        let o4 = p.push(b"ls\r\n");
        assert_eq!(o4.data, b"ls\r\n");
    }

    #[test]
    fn setup_line_has_literal_not_real_marker() {
        let l = setup_line("tok");
        assert!(!l.as_bytes().windows(1).any(|w| w[0] == 0x1b || w[0] == 0x07));
        assert!(l.ends_with('\r'));
    }

    #[test]
    fn batcher_limits() {
        let mut b = Batcher::default();
        assert!(b.take().is_none());
        assert!(b.push(b"abc").is_none());
        let big = vec![0u8; BATCH_MAX_BYTES];
        let full = b.push(&big).unwrap();
        assert_eq!(full.len(), BATCH_MAX_BYTES + 3);
        assert!(b.take().is_none());
    }

    #[test]
    fn plan_forward_merges_and_allowed() {
        let mut last = None;
        let e = plan_input(
            vec![
                InputAction::Forward(b"l".to_vec()),
                InputAction::Forward(b"s".to_vec()),
                InputAction::LineAllowed { line: "ls".into(), normalized: "ls".into() },
                InputAction::Forward(vec![0x0d]),
            ],
            0,
            &mut last,
        );
        assert_eq!(e[0], Effect::Send(b"ls".to_vec()));
        assert!(matches!(e[1], Effect::AuditVerdict { verdict: Verdict::Allow { .. }, .. }));
        assert_eq!(e[2], Effect::Started);
        assert_eq!(e[3], Effect::Send(vec![0x0d]));
    }

    #[test]
    fn plan_denied_audits_notices_and_never_sends_enter_of_line() {
        let mut last = None;
        let e = plan_input(
            vec![
                InputAction::Forward(vec![0x15]),
                InputAction::LineDenied { line: "rm x".into(), reason_code: "no_rule", message: "nope".into() },
            ],
            0,
            &mut last,
        );
        assert_eq!(e[0], Effect::Send(vec![0x15]));
        assert!(matches!(&e[1], Effect::AuditVerdict { verdict: Verdict::Deny { reason_code: "no_rule", .. }, .. }));
        assert!(matches!(&e[2], Effect::Denied { reason_code, .. } if reason_code == "no_rule"));
        assert!(matches!(&e[3], Effect::Notice(s) if s.contains("blocked by Nora policy")));
        assert_eq!(e[4], Effect::Send(vec![0x0d]));
    }

    #[test]
    fn plan_blocked_rate_limited_and_paste() {
        let mut last = None;
        let e = plan_input(vec![InputAction::Blocked { what: "tab" }], 1000, &mut last);
        assert_eq!(e.len(), 2);
        let e = plan_input(vec![InputAction::Blocked { what: "tab" }], 1100, &mut last);
        assert!(e.is_empty());
        let e = plan_input(vec![InputAction::Blocked { what: "tab" }], 1600, &mut last);
        assert_eq!(e.len(), 2);
        let e = plan_input(vec![InputAction::Blocked { what: "empty" }], 9000, &mut last);
        assert!(e.is_empty());
        let e = plan_input(vec![InputAction::PasteRejected { reason: "multiline" }], 0, &mut last);
        assert!(matches!(&e[0], Effect::AuditBlocked { code, .. } if code == "paste_multiline"));
        assert!(e.iter().all(|x| !matches!(x, Effect::Send(_))));
    }

    #[test]
    fn notice_sanitised() {
        let n = notice_line("a\x1b[2Jb\nc");
        assert!(!n.contains("\x1b[2J"));
    }
}
