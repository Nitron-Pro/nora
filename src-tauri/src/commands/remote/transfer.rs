//! Transfer queue for the remote file layer.
//!
//! * `transfer_enqueue` -> id (single file) or group id (recursive directory); directory
//!   recursion expands into one queue item per file.
//! * Worker concurrency defaults to 3 (`transfer_set_concurrency`, 1..=8).
//! * Events: `remote://transfer-progress` `{id, bytes, total, speed_bps, state}` (~10/s per
//!   running item) and `remote://transfer-done` `{id, state, error}`.
//! * Downloads write to `<local>.nora-part` and are renamed on success, so interrupted downloads
//!   resume; uploads write straight to the destination (resumed by appending).
//! * A dropped connection is retried once transparently (reconnect + resume).

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use super::*;

pub const DEFAULT_CONCURRENCY: usize = 3;
pub const MAX_CONCURRENCY: usize = 8;
const MAX_ITEMS: usize = 200_000;
const MAX_DEPTH: usize = 64;
const PART_SUFFIX: &str = ".nora-part";

// ---------------------------------------------------------------------------------------------
// Pure queue state machine (unit tested)
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TState {
    Queued,
    Running,
    Done,
    Failed,
    Cancelled,
}

impl TState {
    pub fn is_finished(self) -> bool {
        matches!(self, TState::Done | TState::Failed | TState::Cancelled)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TransferItem {
    pub id: String,
    pub conn_id: String,
    /// "up" | "down"
    pub direction: String,
    pub local_path: String,
    pub remote_path: String,
    pub state: TState,
    pub bytes: u64,
    pub total: u64,
    pub speed_bps: u64,
    pub error: Option<String>,
    pub group_id: Option<String>,
    pub overwrite: bool,
    pub resume: bool,
    pub created_at: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CancelOutcome {
    NotFound,
    /// Was queued: now cancelled immediately.
    CancelledQueued,
    /// Is running: caller must trigger its cancellation token.
    Running,
    AlreadyFinished,
}

pub struct Queue {
    items: Vec<TransferItem>,
    tokens: HashMap<String, CancellationToken>,
    pub concurrency: usize,
}

impl Queue {
    pub fn new() -> Self {
        Queue { items: Vec::new(), tokens: HashMap::new(), concurrency: DEFAULT_CONCURRENCY }
    }

    pub fn push(&mut self, item: TransferItem) {
        self.tokens.insert(item.id.clone(), CancellationToken::new());
        self.items.push(item);
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn running(&self) -> usize {
        self.items.iter().filter(|i| i.state == TState::Running).count()
    }

    pub fn get(&self, id: &str) -> Option<&TransferItem> {
        self.items.iter().find(|i| i.id == id)
    }

    pub fn token(&self, id: &str) -> Option<CancellationToken> {
        self.tokens.get(id).cloned()
    }

    /// Move the oldest queued item to Running if a worker slot is free.
    pub fn start_next(&mut self) -> Option<TransferItem> {
        if self.running() >= self.concurrency {
            return None;
        }
        let it = self.items.iter_mut().find(|i| i.state == TState::Queued)?;
        it.state = TState::Running;
        Some(it.clone())
    }

    pub fn set_progress(&mut self, id: &str, bytes: u64, total: Option<u64>, speed: u64) {
        if let Some(it) = self.items.iter_mut().find(|i| i.id == id && i.state == TState::Running) {
            it.bytes = bytes;
            it.speed_bps = speed;
            if let Some(t) = total {
                it.total = t;
            }
        }
    }

    /// Record the result of a running item. `Err("CANCELLED")` => cancelled.
    pub fn finish(&mut self, id: &str, result: Result<u64, String>) -> Option<TransferItem> {
        let it = self.items.iter_mut().find(|i| i.id == id)?;
        if it.state.is_finished() {
            return None;
        }
        match result {
            Ok(bytes) => {
                it.state = TState::Done;
                it.bytes = bytes;
                if it.total < bytes {
                    it.total = bytes;
                }
                it.error = None;
            }
            Err(e) if e == "CANCELLED" => {
                it.state = TState::Cancelled;
                it.error = None;
            }
            Err(e) => {
                it.state = TState::Failed;
                it.error = Some(e);
            }
        }
        it.speed_bps = 0;
        let out = it.clone();
        self.tokens.remove(id);
        Some(out)
    }

    pub fn cancel(&mut self, id: &str) -> CancelOutcome {
        let Some(it) = self.items.iter_mut().find(|i| i.id == id) else { return CancelOutcome::NotFound };
        match it.state {
            TState::Queued => {
                it.state = TState::Cancelled;
                self.tokens.remove(id);
                CancelOutcome::CancelledQueued
            }
            TState::Running => CancelOutcome::Running,
            _ => CancelOutcome::AlreadyFinished,
        }
    }

    /// Ids of unfinished items matching `id` as item id or group id (or conn id when `by_conn`).
    pub fn matching_unfinished(&self, id: &str, by_conn: bool) -> Vec<String> {
        self.items
            .iter()
            .filter(|i| !i.state.is_finished())
            .filter(|i| {
                if by_conn {
                    i.conn_id == id
                } else {
                    i.id == id || i.group_id.as_deref() == Some(id)
                }
            })
            .map(|i| i.id.clone())
            .collect()
    }

    pub fn clear_finished(&mut self) -> usize {
        let before = self.items.len();
        self.items.retain(|i| !i.state.is_finished());
        before - self.items.len()
    }

    pub fn list(&self) -> Vec<TransferItem> {
        self.items.clone()
    }
}

// ---------------------------------------------------------------------------------------------
// Global state & scheduler
// ---------------------------------------------------------------------------------------------

struct Engine {
    queue: Mutex<Queue>,
    notify: Notify,
    started: AtomicBool,
}

static ENGINE: OnceLock<Engine> = OnceLock::new();

fn engine() -> &'static Engine {
    ENGINE.get_or_init(|| Engine { queue: Mutex::new(Queue::new()), notify: Notify::new(), started: AtomicBool::new(false) })
}

fn ensure_scheduler(app: &AppHandle) {
    let e = engine();
    if e.started.swap(true, Ordering::SeqCst) {
        return;
    }
    let app = app.clone();
    tokio::spawn(async move {
        let e = engine();
        loop {
            loop {
                let next = e.queue.lock().unwrap().start_next();
                match next {
                    Some(item) => {
                        let app = app.clone();
                        tokio::spawn(async move { run_item(app, item).await });
                    }
                    None => break,
                }
            }
            e.notify.notified().await;
        }
    });
}

#[derive(Serialize, Clone)]
struct ProgressEvent<'a> {
    id: &'a str,
    bytes: u64,
    total: u64,
    speed_bps: u64,
    state: TState,
}

#[derive(Serialize, Clone)]
struct DoneEvent<'a> {
    id: &'a str,
    state: TState,
    error: Option<&'a str>,
}

fn emit_progress(app: &AppHandle, id: &str, bytes: u64, total: u64, speed: u64, state: TState) {
    let _ = app.emit("remote://transfer-progress", ProgressEvent { id, bytes, total, speed_bps: speed, state });
}

fn emit_done(app: &AppHandle, it: &TransferItem) {
    emit_progress(app, &it.id, it.bytes, it.total, 0, it.state);
    let _ = app.emit("remote://transfer-done", DoneEvent { id: &it.id, state: it.state, error: it.error.as_deref() });
}

async fn run_item(app: AppHandle, item: TransferItem) {
    let token = engine().queue.lock().unwrap().token(&item.id).unwrap_or_default();
    emit_progress(&app, &item.id, item.bytes, item.total, 0, TState::Running);

    let progress = Arc::new(AtomicU64::new(0));
    let mut result: Result<u64, String> = Err("not run".into());
    let mut resume = item.resume;

    for attempt in 0..2 {
        progress.store(0, Ordering::Relaxed);
        let fut = execute(&app, &item, resume, &token, progress.clone());
        tokio::pin!(fut);
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        let mut last_bytes = progress.load(Ordering::Relaxed);
        let mut last_t = Instant::now();
        let mut speed = 0f64;
        result = loop {
            tokio::select! {
                r = &mut fut => break r,
                _ = tick.tick() => {
                    let b = progress.load(Ordering::Relaxed);
                    let now = Instant::now();
                    let dt = now.duration_since(last_t).as_secs_f64().max(0.001);
                    let inst = (b.saturating_sub(last_bytes)) as f64 / dt;
                    speed = if speed == 0.0 { inst } else { speed * 0.7 + inst * 0.3 };
                    last_bytes = b;
                    last_t = now;
                    let total = {
                        let mut q = engine().queue.lock().unwrap();
                        q.set_progress(&item.id, b, None, speed as u64);
                        q.get(&item.id).map(|i| i.total).unwrap_or(0)
                    };
                    emit_progress(&app, &item.id, b, total, speed as u64, TState::Running);
                }
            }
        };
        match &result {
            Err(e) if attempt == 0 && is_conn_lost(e) && !token.is_cancelled() => {
                resume = true; // reconnect happens inside execute() on the next lease
                continue;
            }
            _ => break,
        }
    }

    let finished = engine().queue.lock().unwrap().finish(&item.id, result);
    if let Some(it) = finished {
        emit_done(&app, &it);
    }
    engine().notify.notify_one();
}

/// One attempt: lease a connection, honour the overwrite policy, move the bytes.
async fn execute(
    app: &AppHandle,
    item: &TransferItem,
    resume: bool,
    token: &CancellationToken,
    progress: Arc<AtomicU64>,
) -> Result<u64, String> {
    let entry = manager().get(&item.conn_id)?;
    let lease = entry.lease(app).await?;
    let fs = lease.fs.clone();
    let cb = {
        let p = progress.clone();
        move |n: u64| p.store(n, Ordering::Relaxed)
    };
    let res = if item.direction == "down" {
        do_download(&fs, item, resume, &cb, token).await
    } else {
        do_upload(&fs, item, resume, &cb, token).await
    };
    let lost = matches!(&res, Err(e) if is_conn_lost(e));
    entry.release(lease, !lost).await;
    if lost {
        // Replace the shared primary if it is the one that died (no-op for pooled leases).
        let _ = entry.reconnect(app, &fs).await;
    }
    res
}

async fn do_download(
    fs: &Arc<dyn RemoteFs>,
    item: &TransferItem,
    resume: bool,
    cb: &(dyn Fn(u64) + Send + Sync),
    token: &CancellationToken,
) -> Result<u64, String> {
    let dest = PathBuf::from(&item.local_path);
    if !item.overwrite && tokio::fs::try_exists(&dest).await.unwrap_or(false) {
        return Err(format!("EXISTS: {}", item.local_path));
    }
    let part = part_path(&dest);
    let n = fs.download(&item.remote_path, &part, resume, cb, token).await?;
    if tokio::fs::try_exists(&dest).await.unwrap_or(false) {
        tokio::fs::remove_file(&dest).await.map_err(|e| format!("cannot replace local file: {e}"))?;
    }
    tokio::fs::rename(&part, &dest).await.map_err(|e| format!("cannot finalize download: {e}"))?;
    Ok(n)
}

async fn do_upload(
    fs: &Arc<dyn RemoteFs>,
    item: &TransferItem,
    resume: bool,
    cb: &(dyn Fn(u64) + Send + Sync),
    token: &CancellationToken,
) -> Result<u64, String> {
    if !item.overwrite && !resume {
        match fs.stat(&item.remote_path).await {
            Ok(_) => return Err(format!("EXISTS: {}", item.remote_path)),
            Err(e) if is_conn_lost(&e) => return Err(e),
            Err(_) => {}
        }
    }
    fs.upload(Path::new(&item.local_path), &item.remote_path, resume, cb, token).await
}

pub fn part_path(dest: &Path) -> PathBuf {
    let mut s = dest.as_os_str().to_os_string();
    s.push(PART_SUFFIX);
    PathBuf::from(s)
}

// ---------------------------------------------------------------------------------------------
// Enqueue (with directory recursion)
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct TransferSpec {
    pub conn_id: String,
    /// "up" | "down"
    pub direction: String,
    /// File path, or (recursive) the local directory that mirrors the remote directory.
    pub local_path: String,
    /// File path, or (recursive) the remote directory that mirrors the local directory.
    pub remote_path: String,
    #[serde(default)]
    pub overwrite: bool,
    #[serde(default)]
    pub recursive: bool,
    #[serde(default)]
    pub group_id: Option<String>,
    /// Resume partial transfers (default true for downloads, false for uploads).
    #[serde(default)]
    pub resume: Option<bool>,
}

fn validate_local_path(p: &str) -> Result<PathBuf, String> {
    if p.is_empty() || p.contains('\0') {
        return Err("INVALID: bad local path".into());
    }
    let path = PathBuf::from(p);
    if !path.is_absolute() {
        return Err("INVALID: local path must be absolute".into());
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err("INVALID: '..' is not allowed in local paths".into());
    }
    Ok(path)
}

fn new_item(spec: &TransferSpec, dir: &str, local: String, remote: String, total: u64, group: Option<String>) -> TransferItem {
    TransferItem {
        id: uuid::Uuid::new_v4().to_string(),
        conn_id: spec.conn_id.clone(),
        direction: dir.to_string(),
        local_path: local,
        remote_path: remote,
        state: TState::Queued,
        bytes: 0,
        total,
        speed_bps: 0,
        error: None,
        group_id: group,
        overwrite: spec.overwrite,
        resume: spec.resume.unwrap_or(dir == "down"),
        created_at: chrono::Utc::now().timestamp_millis(),
    }
}

fn push_items(items: Vec<TransferItem>) -> Result<(), String> {
    let mut q = engine().queue.lock().unwrap();
    if q.len() + items.len() > MAX_ITEMS {
        return Err("INVALID: transfer queue is full; clear finished transfers".into());
    }
    for i in items {
        q.push(i);
    }
    Ok(())
}

fn failed(mut it: TransferItem, msg: &str) -> TransferItem {
    it.state = TState::Failed;
    it.error = Some(msg.to_string());
    it
}

#[tauri::command]
pub async fn transfer_enqueue(app: AppHandle, spec: TransferSpec) -> Result<String, String> {
    let dir = match spec.direction.as_str() {
        "up" | "upload" => "up",
        "down" | "download" => "down",
        _ => return Err("INVALID: direction must be 'up' or 'down'".into()),
    };
    validate_remote_path(&spec.remote_path)?;
    let local = validate_local_path(&spec.local_path)?;
    let entry = manager().get(&spec.conn_id)?;
    ensure_scheduler(&app);

    let id = if dir == "down" {
        let rp = spec.remote_path.clone();
        let st = entry
            .run(&app, |fs| {
                let p = rp.clone();
                async move { fs.stat(&p).await }
            })
            .await?;
        if st.is_dir() {
            if !spec.recursive {
                return Err("INVALID: remote path is a directory; set recursive".into());
            }
            enqueue_dir_down(&app, &entry, &spec, &local).await?
        } else {
            let it = new_item(&spec, dir, spec.local_path.clone(), spec.remote_path.clone(), st.size, spec.group_id.clone());
            let id = it.id.clone();
            push_items(vec![it])?;
            id
        }
    } else {
        let md = tokio::fs::metadata(&local).await.map_err(|e| format!("cannot read local path: {e}"))?;
        if md.is_dir() {
            if !spec.recursive {
                return Err("INVALID: local path is a directory; set recursive".into());
            }
            enqueue_dir_up(&app, &entry, &spec, &local).await?
        } else {
            let it = new_item(&spec, dir, spec.local_path.clone(), spec.remote_path.clone(), md.len(), spec.group_id.clone());
            let id = it.id.clone();
            push_items(vec![it])?;
            id
        }
    };
    engine().notify.notify_one();
    Ok(id)
}

async fn enqueue_dir_down(app: &AppHandle, entry: &Arc<ConnEntry>, spec: &TransferSpec, local_root: &Path) -> Result<String, String> {
    let group = spec.group_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    tokio::fs::create_dir_all(local_root).await.map_err(|e| format!("cannot create local folder: {e}"))?;
    let mut stack: Vec<(String, PathBuf, usize)> = vec![(spec.remote_path.clone(), local_root.to_path_buf(), 0)];
    let mut items = Vec::new();
    while let Some((rdir, ldir, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            continue;
        }
        let rd = rdir.clone();
        let entries = entry
            .run(app, |fs| {
                let p = rd.clone();
                async move { fs.list(&p).await }
            })
            .await?;
        for e in entries {
            let target = join_local(&ldir, &e.name);
            let make = |total: u64| {
                new_item(
                    spec,
                    "down",
                    target.as_ref().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default(),
                    e.path.clone(),
                    total,
                    Some(group.clone()),
                )
            };
            let Some(tp) = target.clone() else {
                items.push(failed(make(0), "INVALID: unsafe file name from server"));
                continue;
            };
            if e.kind == "dir" {
                tokio::fs::create_dir_all(&tp).await.map_err(|er| format!("cannot create local folder: {er}"))?;
                stack.push((e.path.clone(), tp, depth + 1));
            } else if e.kind == "symlink" && e.target_is_dir == Some(true) {
                continue; // never follow directory links (loops)
            } else {
                items.push(make(e.size));
            }
            if items.len() > MAX_ITEMS {
                return Err("INVALID: too many files in directory tree".into());
            }
        }
    }
    push_items(items)?;
    Ok(group)
}

/// Map a remote name onto the local disk; `None` for names that could escape `dir`.
fn join_local(dir: &Path, name: &str) -> Option<PathBuf> {
    if is_safe_local_component(name) {
        Some(dir.join(name))
    } else {
        None
    }
}

async fn enqueue_dir_up(app: &AppHandle, entry: &Arc<ConnEntry>, spec: &TransferSpec, local_root: &Path) -> Result<String, String> {
    let group = spec.group_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let root = local_root.to_path_buf();
    // (relative path components, is_dir, size)
    let walked = tokio::task::spawn_blocking(move || walk_local(&root))
        .await
        .map_err(|e| e.to_string())??;

    let rroot = spec.remote_path.clone();
    entry
        .run(app, |fs| {
            let p = rroot.clone();
            async move { fs.mkdir(&p, true).await }
        })
        .await?;

    let mut items = Vec::new();
    for (rel, is_dir, size) in walked {
        let remote = rel.iter().fold(spec.remote_path.clone(), |acc, c| join_path(&acc, c));
        if validate_remote_path(&remote).is_err() {
            continue;
        }
        if is_dir {
            let r = remote.clone();
            entry
                .run(app, |fs| {
                    let p = r.clone();
                    async move { fs.mkdir(&p, true).await }
                })
                .await?;
        } else {
            let local = rel.iter().fold(local_root.to_path_buf(), |acc, c| acc.join(c));
            items.push(new_item(spec, "up", local.to_string_lossy().into_owned(), remote, size, Some(group.clone())));
        }
    }
    push_items(items)?;
    Ok(group)
}

type Walked = Vec<(Vec<String>, bool, u64)>;

fn walk_local(root: &Path) -> Result<Walked, String> {
    let mut out: Walked = Vec::new();
    let mut stack: Vec<(PathBuf, Vec<String>)> = vec![(root.to_path_buf(), Vec::new())];
    while let Some((dir, rel)) = stack.pop() {
        if rel.len() > MAX_DEPTH {
            continue;
        }
        let rd = std::fs::read_dir(&dir).map_err(|e| format!("cannot read '{}': {e}", dir.display()))?;
        for ent in rd {
            let ent = ent.map_err(|e| e.to_string())?;
            let ft = ent.file_type().map_err(|e| e.to_string())?;
            if ft.is_symlink() {
                continue; // do not follow links
            }
            let Some(name) = ent.file_name().to_str().map(str::to_string) else { continue };
            if name.ends_with(PART_SUFFIX) && ft.is_file() {
                continue;
            }
            let mut r = rel.clone();
            r.push(name);
            if ft.is_dir() {
                out.push((r.clone(), true, 0));
                stack.push((ent.path(), r));
            } else if ft.is_file() {
                let size = ent.metadata().map(|m| m.len()).unwrap_or(0);
                out.push((r, false, size));
            }
            if out.len() > MAX_ITEMS {
                return Err("INVALID: too many files in directory tree".into());
            }
        }
    }
    // Parents before children so mkdir order is natural.
    out.sort_by(|a, b| a.0.len().cmp(&b.0.len()));
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// IPC
// ---------------------------------------------------------------------------------------------

/// Cancels the item with this id, or every unfinished item of the group with this id.
#[tauri::command]
pub async fn transfer_cancel(app: AppHandle, id: String) -> Result<(), String> {
    cancel_matching(&app, &id, false);
    Ok(())
}

fn cancel_matching(app: &AppHandle, id: &str, by_conn: bool) {
    let ids = engine().queue.lock().unwrap().matching_unfinished(id, by_conn);
    for i in ids {
        let (outcome, token, item) = {
            let mut q = engine().queue.lock().unwrap();
            let o = q.cancel(&i);
            (o, q.token(&i), q.get(&i).cloned())
        };
        match outcome {
            CancelOutcome::Running => {
                if let Some(t) = token {
                    t.cancel();
                }
            }
            CancelOutcome::CancelledQueued => {
                if let Some(it) = item {
                    emit_done(app, &it);
                }
            }
            _ => {}
        }
    }
}

/// Called by `remote_disconnect`. Cancels running tokens and queued items of the connection.
pub fn cancel_connection(conn_id: &str) {
    let ids = engine().queue.lock().unwrap().matching_unfinished(conn_id, true);
    let mut q = engine().queue.lock().unwrap();
    for i in ids {
        if q.cancel(&i) == CancelOutcome::Running {
            if let Some(t) = q.token(&i) {
                t.cancel();
            }
        }
    }
}

#[tauri::command]
pub async fn transfer_list() -> Result<Vec<TransferItem>, String> {
    Ok(engine().queue.lock().unwrap().list())
}

#[tauri::command]
pub async fn transfer_set_concurrency(n: usize) -> Result<usize, String> {
    let n = n.clamp(1, MAX_CONCURRENCY);
    engine().queue.lock().unwrap().concurrency = n;
    engine().notify.notify_one();
    Ok(n)
}

/// Removes done / failed / cancelled items; returns how many were removed.
#[tauri::command]
pub async fn transfer_clear_finished() -> Result<usize, String> {
    Ok(engine().queue.lock().unwrap().clear_finished())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str, group: Option<&str>) -> TransferItem {
        TransferItem {
            id: id.into(),
            conn_id: "c1".into(),
            direction: "down".into(),
            local_path: "C:\\x".into(),
            remote_path: "/x".into(),
            state: TState::Queued,
            bytes: 0,
            total: 10,
            speed_bps: 0,
            error: None,
            group_id: group.map(String::from),
            overwrite: false,
            resume: true,
            created_at: 0,
        }
    }

    #[test]
    fn respects_concurrency_and_fifo() {
        let mut q = Queue::new();
        q.concurrency = 2;
        for i in ["a", "b", "c"] {
            q.push(item(i, None));
        }
        assert_eq!(q.start_next().unwrap().id, "a");
        assert_eq!(q.start_next().unwrap().id, "b");
        assert!(q.start_next().is_none());
        q.finish("a", Ok(10));
        assert_eq!(q.start_next().unwrap().id, "c");
    }

    #[test]
    fn finish_states() {
        let mut q = Queue::new();
        q.push(item("a", None));
        q.push(item("b", None));
        q.push(item("c", None));
        for _ in 0..3 {
            q.start_next();
        }
        assert_eq!(q.finish("a", Ok(10)).unwrap().state, TState::Done);
        assert_eq!(q.finish("b", Err("CANCELLED".into())).unwrap().state, TState::Cancelled);
        let c = q.finish("c", Err("boom".into())).unwrap();
        assert_eq!(c.state, TState::Failed);
        assert_eq!(c.error.as_deref(), Some("boom"));
        // Finishing twice is ignored.
        assert!(q.finish("a", Err("x".into())).is_none());
    }

    #[test]
    fn cancel_semantics() {
        let mut q = Queue::new();
        q.concurrency = 1;
        q.push(item("a", Some("g")));
        q.push(item("b", Some("g")));
        q.start_next();
        assert_eq!(q.cancel("b"), CancelOutcome::CancelledQueued);
        assert_eq!(q.cancel("a"), CancelOutcome::Running);
        assert_eq!(q.cancel("zzz"), CancelOutcome::NotFound);
        q.finish("a", Err("CANCELLED".into()));
        assert_eq!(q.cancel("a"), CancelOutcome::AlreadyFinished);
        // cancelled queued item is never started
        assert!(q.start_next().is_none());
    }

    #[test]
    fn group_matching_and_clear() {
        let mut q = Queue::new();
        q.push(item("a", Some("g")));
        q.push(item("b", Some("g")));
        q.push(item("c", None));
        assert_eq!(q.matching_unfinished("g", false).len(), 2);
        assert_eq!(q.matching_unfinished("c1", true).len(), 3);
        q.start_next();
        q.finish("a", Ok(1));
        assert_eq!(q.clear_finished(), 1);
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn progress_only_while_running() {
        let mut q = Queue::new();
        q.push(item("a", None));
        q.set_progress("a", 5, None, 1); // queued: ignored
        assert_eq!(q.get("a").unwrap().bytes, 0);
        q.start_next();
        q.set_progress("a", 5, Some(20), 100);
        let it = q.get("a").unwrap();
        assert_eq!((it.bytes, it.total, it.speed_bps), (5, 20, 100));
    }

    #[test]
    fn local_path_rules() {
        assert!(validate_local_path("relative/x").is_err());
        assert!(validate_local_path("").is_err());
        #[cfg(windows)]
        {
            assert!(validate_local_path("C:\\a\\..\\b").is_err());
            assert!(validate_local_path("C:\\a\\b").is_ok());
        }
    }

    #[test]
    fn join_local_blocks_traversal() {
        let d = Path::new("D:\\dl");
        assert!(join_local(d, "ok.txt").is_some());
        assert!(join_local(d, "..").is_none());
        assert!(join_local(d, "a\\b").is_none());
        assert!(join_local(d, "..\\evil").is_none());
    }

    #[test]
    fn part_file_name() {
        assert_eq!(part_path(Path::new("D:\\a\\b.zip")), PathBuf::from("D:\\a\\b.zip.nora-part"));
    }
}
