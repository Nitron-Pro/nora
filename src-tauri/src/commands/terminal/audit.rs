//! Persistent JSONL audit log of terminal commands.
//!
//! Files live ONLY in `<exe_dir>/nora-data/logs/` (via `crate::portable::data_subdir("logs")`):
//! `commands-YYYYMM.jsonl` (UTC month). When a file reaches [`MAX_FILE_BYTES`] it is renamed to
//! `commands-YYYYMM.N.jsonl` and a fresh file is started; at most [`MAX_FILES`] files are kept.
//! One JSON object per line: `ts, conn_id, user_label, source, line, verdict, reason_code`.
//!
//! [`record`] never blocks the caller (entries go through a channel to a writer thread), never
//! panics and swallows errors to stderr. Lines are passed through [`redact`] before being stored.
//! The Tauri command [`terminal_audit_list`] is defined here but registered elsewhere.

use crate::commands::terminal::guard::Verdict;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// Rotate when a log file reaches this size.
pub const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;
/// Keep at most this many log files (oldest are deleted on rotation).
pub const MAX_FILES: usize = 36;
const MAX_LINE_CHARS: usize = 4096;

/// Where the command came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Pty,
    Exec,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Source::Pty => "pty",
            Source::Exec => "exec",
        }
    }
}

/// Outcome stored in the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditVerdict {
    Allow,
    Deny,
    /// Input swallowed without being a command (rejected paste, ...).
    Blocked,
}

impl AuditVerdict {
    fn as_str(self) -> &'static str {
        match self {
            AuditVerdict::Allow => "allow",
            AuditVerdict::Deny => "deny",
            AuditVerdict::Blocked => "blocked",
        }
    }
}

/// One stored record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditEntry {
    /// UTC, `YYYY-MM-DDTHH:MM:SS.mmmZ` (lexicographically sortable).
    pub ts: String,
    pub conn_id: String,
    pub user_label: String,
    /// `pty` | `exec`
    pub source: String,
    /// Redacted command line.
    pub line: String,
    /// `allow` | `deny` | `blocked`
    pub verdict: String,
    pub reason_code: Option<String>,
}

/// Filter for [`list`] / `terminal_audit_list`. All fields optional (AND-combined).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditFilter {
    pub conn_id: Option<String>,
    /// `pty` | `exec`
    pub source: Option<String>,
    /// `allow` | `deny` | `blocked`
    pub verdict: Option<String>,
    /// Case-insensitive substring of the line.
    pub text: Option<String>,
    /// Inclusive lower bound, RFC3339/ISO string compared with `ts`.
    pub since: Option<String>,
    /// Inclusive upper bound.
    pub until: Option<String>,
    /// Max rows (default 200, hard cap 5000).
    pub limit: Option<usize>,
}

// ---------------------------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------------------------

const SECRET_KEY_PARTS: &[&str] = &[
    "pass", "pwd", "secret", "token", "apikey", "api_key", "api-key", "auth", "credential",
    "private", "access_key", "accesskey",
];
const SECRET_PREFIXES: &[&str] = &["ghp_", "gho_", "ghs_", "github_pat_", "xoxb-", "xoxp-", "xoxa-", "sk-", "AKIA", "eyJ"];

fn is_secret_key(k: &str) -> bool {
    let k = k.trim_start_matches('-').to_ascii_lowercase();
    !k.is_empty() && SECRET_KEY_PARTS.iter().any(|p| k.contains(p))
}

/// Mask obvious secrets: `password=...`, `--password x`, `-pSECRET`, `Authorization: Bearer x`,
/// `scheme://user:pw@host`, well-known token prefixes. Best effort, errs on over-redaction.
pub fn redact(line: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut hide_next: u8 = 0;
    let mut open_quote: Option<char> = None;

    for tok in line.split(' ') {
        // Continue a quoted secret value that spans several tokens.
        if let Some(q) = open_quote {
            if tok.ends_with(q) {
                open_quote = None;
            }
            continue;
        }
        if hide_next > 0 {
            hide_next -= 1;
            out.push("***".into());
            continue;
        }
        let lower = tok.to_ascii_lowercase();
        let bare = tok.trim_matches(|c| c == '\'' || c == '"');

        if let Some(eq) = tok.find('=') {
            let (k, v) = tok.split_at(eq);
            if is_secret_key(k) {
                let v = &v[1..];
                if let Some(q) = v.chars().next().filter(|c| *c == '\'' || *c == '"') {
                    if v.len() == 1 || !v.ends_with(q) {
                        open_quote = Some(q);
                    }
                }
                out.push(format!("{k}=***"));
                continue;
            }
        }
        if let Some(colon) = tok.find(':') {
            let k = &tok[..colon];
            if lower.starts_with("authorization") && k.len() == "authorization".len() {
                out.push(format!("{k}:"));
                hide_next = 2;
                continue;
            }
        }
        if tok.len() > 2 && tok.starts_with("-p") && !tok.starts_with("--") {
            out.push("-p***".into());
            continue;
        }
        if tok.starts_with('-') && !tok.contains('=') && is_secret_key(tok) {
            out.push(tok.to_string());
            hide_next = 1;
            continue;
        }
        if lower == "bearer" || lower == "basic" {
            out.push(tok.to_string());
            hide_next = 1;
            continue;
        }
        if bare.len() >= 16 && SECRET_PREFIXES.iter().any(|p| bare.starts_with(p)) {
            out.push("***".into());
            continue;
        }
        if let Some(sch) = tok.find("://") {
            let rest = &tok[sch + 3..];
            if let (Some(colon), Some(at)) = (rest.find(':'), rest.find('@')) {
                if colon < at {
                    out.push(format!("{}://{}:***{}", &tok[..sch], &rest[..colon], &rest[at..]));
                    continue;
                }
            }
        }
        out.push(tok.to_string());
    }
    out.join(" ")
}

fn sanitize_line(line: &str) -> String {
    let red = redact(line);
    let cleaned: String = red
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .take(MAX_LINE_CHARS)
        .collect();
    cleaned
}

// ---------------------------------------------------------------------------------------------
// File layer (directory is a parameter so tests can use a project-local folder)
// ---------------------------------------------------------------------------------------------

fn month_of(ts: &str) -> String {
    // ts = YYYY-MM-DD...
    let d: String = ts.chars().filter(|c| c.is_ascii_digit()).take(6).collect();
    if d.len() == 6 {
        d
    } else {
        "000000".into()
    }
}

fn is_log_file(name: &str) -> bool {
    name.starts_with("commands-") && name.ends_with(".jsonl")
}

fn list_log_files(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_name().to_str().map(is_log_file).unwrap_or(false))
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

fn rotate_if_needed(dir: &Path, current: &Path, month: &str, max_bytes: u64) {
    let size = fs::metadata(current).map(|m| m.len()).unwrap_or(0);
    if size < max_bytes {
        return;
    }
    let mut n = 1u32;
    loop {
        let target = dir.join(format!("commands-{month}.{n}.jsonl"));
        if !target.exists() {
            if let Err(e) = fs::rename(current, &target) {
                eprintln!("[terminal-audit] rotation failed: {e}");
            }
            break;
        }
        n += 1;
        if n > 100_000 {
            break;
        }
    }
    // Retention: delete oldest beyond MAX_FILES.
    let files = list_log_files(dir);
    if files.len() > MAX_FILES {
        for old in &files[..files.len() - MAX_FILES] {
            let _ = fs::remove_file(old);
        }
    }
}

/// Append an entry to the proper file inside `dir`.
pub(crate) fn write_entry(dir: &Path, entry: &AuditEntry, max_bytes: u64) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| format!("create log dir: {e}"))?;
    let month = month_of(&entry.ts);
    let path = dir.join(format!("commands-{month}.jsonl"));
    rotate_if_needed(dir, &path, &month, max_bytes);
    let mut json = serde_json::to_string(entry).map_err(|e| e.to_string())?;
    json.push('\n');
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    f.write_all(json.as_bytes())
        .map_err(|e| format!("write {}: {e}", path.display()))
}

fn matches(f: &AuditFilter, e: &AuditEntry) -> bool {
    f.conn_id.as_ref().map_or(true, |x| *x == e.conn_id)
        && f.source.as_ref().map_or(true, |x| *x == e.source)
        && f.verdict.as_ref().map_or(true, |x| *x == e.verdict)
        && f
            .text
            .as_ref()
            .map_or(true, |x| e.line.to_lowercase().contains(&x.to_lowercase()))
        && f.since.as_ref().map_or(true, |x| e.ts.as_str() >= x.as_str())
        && f.until.as_ref().map_or(true, |x| e.ts.as_str() <= x.as_str())
}

/// Read entries from `dir`, newest first.
pub(crate) fn list_in(dir: &Path, filter: &AuditFilter, limit: usize) -> Vec<AuditEntry> {
    let mut rows: Vec<AuditEntry> = Vec::new();
    for path in list_log_files(dir) {
        let Ok(f) = fs::File::open(&path) else { continue };
        for line in BufReader::new(f).lines().map_while(Result::ok) {
            if let Ok(e) = serde_json::from_str::<AuditEntry>(&line) {
                if matches(filter, &e) {
                    rows.push(e);
                }
            }
        }
    }
    rows.sort_by(|a, b| b.ts.cmp(&a.ts));
    rows.truncate(limit);
    rows
}

// ---------------------------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------------------------

enum Msg {
    Entry(AuditEntry),
    Flush(Sender<()>),
}

static WRITER: OnceLock<Mutex<Sender<Msg>>> = OnceLock::new();

fn writer() -> &'static Mutex<Sender<Msg>> {
    WRITER.get_or_init(|| {
        let (tx, rx) = channel::<Msg>();
        let spawned = std::thread::Builder::new()
            .name("terminal-audit".into())
            .spawn(move || {
                while let Ok(msg) = rx.recv() {
                    match msg {
                        Msg::Entry(e) => {
                            let res = crate::portable::data_subdir("logs")
                                .and_then(|d| write_entry(&d, &e, MAX_FILE_BYTES));
                            if let Err(err) = res {
                                eprintln!("[terminal-audit] write failed: {err}");
                            }
                        }
                        Msg::Flush(ack) => {
                            let _ = ack.send(());
                        }
                    }
                }
            });
        if let Err(e) = spawned {
            eprintln!("[terminal-audit] cannot start writer thread: {e}");
        }
        Mutex::new(tx)
    })
}

/// Wait (max 2 s) until everything queued so far has been written.
pub fn flush() {
    let (ack_tx, ack_rx) = channel();
    let sent = writer()
        .lock()
        .map(|tx| tx.send(Msg::Flush(ack_tx)).is_ok())
        .unwrap_or(false);
    if sent {
        let _ = ack_rx.recv_timeout(Duration::from_secs(2));
    }
}

/// Queue an audit record (non-blocking, never panics). `line` is redacted here.
pub fn record(
    conn_id: &str,
    user_label: &str,
    source: Source,
    line: &str,
    verdict: AuditVerdict,
    reason_code: Option<&str>,
) {
    let entry = AuditEntry {
        ts: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        conn_id: conn_id.chars().take(128).collect(),
        user_label: user_label.chars().take(128).collect(),
        source: source.as_str().to_string(),
        line: sanitize_line(line),
        verdict: verdict.as_str().to_string(),
        reason_code: reason_code.map(|s| s.chars().take(64).collect()),
    };
    match writer().lock() {
        Ok(tx) => {
            if tx.send(Msg::Entry(entry)).is_err() {
                eprintln!("[terminal-audit] writer thread is gone; entry lost");
            }
        }
        Err(_) => eprintln!("[terminal-audit] writer lock poisoned; entry lost"),
    }
}

/// Convenience: record a guard [`Verdict`].
pub fn record_verdict(conn_id: &str, user_label: &str, source: Source, line: &str, v: &Verdict) {
    match v {
        Verdict::Allow { .. } => record(conn_id, user_label, source, line, AuditVerdict::Allow, None),
        Verdict::Deny { reason_code, .. } => {
            record(conn_id, user_label, source, line, AuditVerdict::Deny, Some(reason_code))
        }
    }
}

/// Read records, newest first. `limit` is clamped to 1..=5000.
pub fn list(filter: &AuditFilter, limit: usize) -> Result<Vec<AuditEntry>, String> {
    flush();
    let dir = crate::portable::data_subdir("logs")?;
    Ok(list_in(&dir, filter, limit.clamp(1, 5000)))
}

/// IPC: `terminal_audit_list` - returns audit rows, newest first (default 200, max 5000).
#[tauri::command]
pub async fn terminal_audit_list(filter: Option<AuditFilter>) -> Result<Vec<AuditEntry>, String> {
    let filter = filter.unwrap_or_default();
    let limit = filter.limit.unwrap_or(200);
    tokio::task::spawn_blocking(move || list(&filter, limit))
        .await
        .map_err(|e| format!("audit task failed: {e}"))?
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(name: &str) -> PathBuf {
        let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("audit-tests")
            .join(name);
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn entry(ts: &str, line: &str, verdict: &str) -> AuditEntry {
        AuditEntry {
            ts: ts.into(),
            conn_id: "c1".into(),
            user_label: "u".into(),
            source: "pty".into(),
            line: line.into(),
            verdict: verdict.into(),
            reason_code: None,
        }
    }

    #[test]
    fn redacts_key_value() {
        assert_eq!(redact("mysql --password=hunter2 db"), "mysql --password=*** db");
        assert_eq!(redact("export DB_PASSWORD=abc"), "export DB_PASSWORD=***");
        assert_eq!(redact("curl token=abc123 x"), "curl token=*** x");
        assert_eq!(redact("PASSWD='a b c' ls"), "PASSWD=*** ls");
    }

    #[test]
    fn redacts_flags_and_dash_p() {
        assert_eq!(redact("tool --password hunter2 run"), "tool --password *** run");
        assert_eq!(redact("tool --api-key KEY run"), "tool --api-key *** run");
        assert_eq!(redact("mysql -uroot -psecret db"), "mysql -uroot -p*** db");
    }

    #[test]
    fn redacts_bearer_url_prefixes() {
        assert_eq!(redact("curl -H Authorization: Bearer abc.def"), "curl -H Authorization: *** ***");
        assert_eq!(redact("curl Bearer abc"), "curl Bearer ***");
        assert_eq!(
            redact("git clone https://bob:pw123@host/x.git"),
            "git clone https://bob:***@host/x.git"
        );
        assert_eq!(redact("echo ghp_abcdefghijklmnopqrstuv"), "echo ***");
        assert_eq!(redact("echo AKIAABCDEFGHIJKLMNOP"), "echo ***");
    }

    #[test]
    fn redact_leaves_normal_lines() {
        assert_eq!(redact("ls -la /var/www"), "ls -la /var/www");
        assert_eq!(redact("php bin/console cache:clear"), "php bin/console cache:clear");
    }

    #[test]
    fn sanitize_strips_control_chars() {
        assert_eq!(sanitize_line("ls\n\x1b[31m"), "ls??[31m");
    }

    #[test]
    fn write_and_list_roundtrip() {
        let d = test_dir("roundtrip");
        write_entry(&d, &entry("2026-03-01T10:00:00.000Z", "ls", "allow"), MAX_FILE_BYTES).unwrap();
        write_entry(&d, &entry("2026-03-02T10:00:00.000Z", "rm x", "deny"), MAX_FILE_BYTES).unwrap();
        write_entry(&d, &entry("2026-04-01T10:00:00.000Z", "pwd", "allow"), MAX_FILE_BYTES).unwrap();
        assert!(d.join("commands-202603.jsonl").exists());
        assert!(d.join("commands-202604.jsonl").exists());
        let all = list_in(&d, &AuditFilter::default(), 100);
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].line, "pwd"); // newest first
        let denied = list_in(
            &d,
            &AuditFilter {
                verdict: Some("deny".into()),
                ..Default::default()
            },
            100,
        );
        assert_eq!(denied.len(), 1);
        let txt = list_in(
            &d,
            &AuditFilter {
                text: Some("RM".into()),
                ..Default::default()
            },
            100,
        );
        assert_eq!(txt.len(), 1);
        assert_eq!(list_in(&d, &AuditFilter::default(), 2).len(), 2);
        let since = list_in(
            &d,
            &AuditFilter {
                since: Some("2026-03-02".into()),
                ..Default::default()
            },
            100,
        );
        assert_eq!(since.len(), 2);
    }

    #[test]
    fn rotation_by_size() {
        let d = test_dir("rotation");
        for i in 0..6 {
            write_entry(
                &d,
                &entry(&format!("2026-05-01T10:00:0{i}.000Z"), "ls", "allow"),
                200, // tiny limit
            )
            .unwrap();
        }
        let files = list_log_files(&d);
        assert!(files.len() > 1, "expected rotated files, got {files:?}");
        assert_eq!(list_in(&d, &AuditFilter::default(), 100).len(), 6);
    }

    #[test]
    fn list_skips_garbage_lines() {
        let d = test_dir("garbage");
        fs::write(d.join("commands-202601.jsonl"), "not json\n{\"x\":1}\n").unwrap();
        write_entry(&d, &entry("2026-01-05T00:00:00.000Z", "ls", "allow"), MAX_FILE_BYTES).unwrap();
        assert_eq!(list_in(&d, &AuditFilter::default(), 10).len(), 1);
    }

    #[test]
    fn list_missing_dir_is_empty() {
        let d = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target").join("audit-tests").join("nonexistent-xyz");
        assert!(list_in(&d, &AuditFilter::default(), 10).is_empty());
    }
}
