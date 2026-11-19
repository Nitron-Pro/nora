//! Local snapshot engine on top of libgit2 (`git2`, vendored, no system git needed).
//!
//! Snapshots live in a BARE repository (no worktree). A commit is built by copying arbitrary local
//! files (or inline base64 content) into the object database and assembling the tree in memory,
//! so the committed file set does not have to be a working tree of the repo.
//!
//! Repo location: the `repo` argument is either an absolute/relative path, or a plain repo id
//! (`[A-Za-z0-9_.-]+`) which maps to `<exe_dir>/nora-data/snapshots/<id>` (Zero C-Drive).

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Once, OnceLock};

use base64::Engine;
use git2::{ObjectType, Oid, Repository, RepositoryInitOptions, Signature, TreeWalkMode, TreeWalkResult};
use serde::{Deserialize, Serialize};

const MAX_INLINE_BYTES: usize = 64 * 1024 * 1024;
const MAX_PATCH_FILE_BYTES: u64 = 1024 * 1024;
const MAX_PATCH_TOTAL_BYTES: usize = 4 * 1024 * 1024;
const MAX_DIFF_FILES: usize = 5000;
const MAX_WORKDIR_FILES: usize = 100_000;
const MAX_LOG_LIMIT: usize = 1000;
const MAX_READ_BYTES: u64 = 32 * 1024 * 1024;
const TRAILER: &str = "Nora-Metadata: ";

// ---------------------------------------------------------------- helpers

fn init_libgit2() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // Repos may sit on removable/other-owner drives; ownership validation would reject them.
        unsafe {
            let _ = git2::opts::set_verify_owner_validation(false);
        }
    });
}

fn ge<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

fn repo_lock(path: &Path) -> Arc<Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();
    let map = LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut g = map.lock().unwrap_or_else(|p| p.into_inner());
    g.entry(path.to_path_buf()).or_default().clone()
}

fn is_repo_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s != "."
        && s != ".."
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// Resolve the `repo` argument (path or id) to a directory path.
fn resolve_repo_path(repo: &str) -> Result<PathBuf, String> {
    if is_repo_id(repo) {
        Ok(crate::portable::data_subdir("snapshots")?.join(repo))
    } else if repo.trim().is_empty() {
        Err("empty repo".into())
    } else {
        Ok(PathBuf::from(repo))
    }
}

fn open_repo(repo: &str) -> Result<(Repository, PathBuf), String> {
    init_libgit2();
    let p = resolve_repo_path(repo)?;
    let r = Repository::open(&p).map_err(|e| format!("cannot open snapshot repo '{}': {e}", p.display()))?;
    Ok((r, p))
}

/// Validate and normalize a repo-relative path (`/` separators, no traversal).
pub fn clean_rel_path(p: &str) -> Result<String, String> {
    let s = p.replace('\\', "/");
    if s.is_empty() || s.contains('\0') || s.starts_with('/') {
        return Err(format!("invalid repo-relative path: '{p}'"));
    }
    let mut parts = Vec::new();
    for c in s.split('/') {
        if c.is_empty() || c == "." || c == ".." || c.contains(':') || c.eq_ignore_ascii_case(".git") {
            return Err(format!("invalid repo-relative path: '{p}'"));
        }
        parts.push(c);
    }
    Ok(parts.join("/"))
}

fn sig() -> Result<Signature<'static>, String> {
    Signature::now("Nora", "nora@localhost").map_err(ge)
}

fn resolve_commit<'r>(repo: &'r Repository, spec: &str) -> Result<git2::Commit<'r>, String> {
    let obj = repo
        .revparse_single(spec)
        .map_err(|e| format!("cannot resolve '{spec}': {e}"))?;
    obj.peel_to_commit().map_err(|e| format!("'{spec}' is not a commit: {e}"))
}

fn split_message(full: &str) -> (String, Option<serde_json::Value>) {
    if let Some(idx) = full.rfind(TRAILER) {
        let (head, tail) = full.split_at(idx);
        let json = tail[TRAILER.len()..].trim();
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(json) {
            return (head.trim_end().to_string(), Some(v));
        }
    }
    (full.trim_end().to_string(), None)
}

/// Flatten a tree into `path -> (blob oid, filemode)`.
fn flatten(repo: &Repository, tree: &git2::Tree) -> Result<BTreeMap<String, (Oid, i32)>, String> {
    let mut out = BTreeMap::new();
    let _ = repo;
    tree.walk(TreeWalkMode::PreOrder, |root, e| {
        if e.kind() == Some(ObjectType::Blob) {
            if let Ok(n) = e.name() {
                out.insert(format!("{root}{n}"), (e.id(), e.filemode()));
            }
        }
        TreeWalkResult::Ok
    })
    .map_err(ge)?;
    Ok(out)
}

#[derive(Default)]
struct Node {
    files: BTreeMap<String, (Oid, i32)>,
    dirs: BTreeMap<String, Node>,
}

fn write_node(repo: &Repository, n: &Node) -> Result<Oid, String> {
    let mut tb = repo.treebuilder(None).map_err(ge)?;
    for (name, (oid, mode)) in &n.files {
        tb.insert(name, *oid, *mode).map_err(ge)?;
    }
    for (name, d) in &n.dirs {
        let oid = write_node(repo, d)?;
        tb.insert(name, oid, 0o040000).map_err(ge)?;
    }
    tb.write().map_err(ge)
}

fn build_tree(repo: &Repository, map: &BTreeMap<String, (Oid, i32)>) -> Result<Oid, String> {
    let mut root = Node::default();
    for (path, v) in map {
        let parts: Vec<&str> = path.split('/').collect();
        let mut cur = &mut root;
        for d in &parts[..parts.len() - 1] {
            cur = cur.dirs.entry((*d).to_string()).or_default();
        }
        cur.files.insert(parts[parts.len() - 1].to_string(), *v);
    }
    write_node(repo, &root)
}

/// Returns the blob content at `path` in `commit`, or None when the file did not exist.
fn read_blob(repo: &Repository, commit: &git2::Commit, path: &str) -> Result<Option<Vec<u8>>, String> {
    let tree = commit.tree().map_err(ge)?;
    match tree.get_path(Path::new(path)) {
        Ok(entry) => {
            if entry.kind() != Some(ObjectType::Blob) {
                return Err(format!("'{path}' is not a file"));
            }
            let b = repo.find_blob(entry.id()).map_err(ge)?;
            Ok(Some(b.content().to_vec()))
        }
        Err(e) if e.code() == git2::ErrorCode::NotFound => Ok(None),
        Err(e) => Err(ge(e)),
    }
}

fn blob_oid_at(commit: &git2::Commit, path: &str) -> Option<Oid> {
    commit.tree().ok()?.get_path(Path::new(path)).ok().map(|e| e.id())
}

async fn run<T: Send + 'static>(f: impl FnOnce() -> Result<T, String> + Send + 'static) -> Result<T, String> {
    tokio::task::spawn_blocking(f).await.map_err(|e| format!("task failed: {e}"))?
}

// ---------------------------------------------------------------- types

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitResult {
    pub repo: String,
    pub created: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileSpec {
    /// Repo-relative path.
    pub path: String,
    /// Copy content from this local file.
    pub local_path: Option<String>,
    /// Inline content (base64).
    pub content_base64: Option<String>,
    /// The file did not exist: record it as deleted/absent.
    pub absent: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    pub id: String,
    pub short_id: String,
    pub message: String,
    pub metadata: Option<serde_json::Value>,
    pub time: i64,
    pub tags: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffFile {
    pub path: String,
    /// "added" | "removed" | "modified"
    pub status: String,
    pub binary: bool,
    pub old_size: u64,
    pub new_size: u64,
    /// Unified patch (None for binary / too large / over budget).
    pub patch: Option<String>,
    pub patch_skipped: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffResult {
    pub files: Vec<DiffFile>,
    pub truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreResult {
    /// "restored" | "absent"
    pub status: String,
    pub bytes: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TagInfo {
    pub name: String,
    pub commit_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadResult {
    pub absent: bool,
    pub size: u64,
    pub truncated: bool,
    pub binary: bool,
    pub content_base64: String,
}

// ---------------------------------------------------------------- commands

/// Create (or open) a bare snapshot repo. Give `repoPath` or `repoId` (default location).
#[tauri::command]
pub async fn snapshot_init(repo_path: Option<String>, repo_id: Option<String>) -> Result<InitResult, String> {
    run(move || {
        init_libgit2();
        let p = match (repo_path, repo_id) {
            (Some(p), _) if !p.trim().is_empty() => PathBuf::from(p),
            (_, Some(id)) => {
                if !is_repo_id(&id) {
                    return Err(format!("invalid repo id: '{id}'"));
                }
                crate::portable::data_subdir("snapshots")?.join(id)
            }
            _ => return Err("repoPath or repoId is required".into()),
        };
        let lock = repo_lock(&p);
        let _g = lock.lock().unwrap_or_else(|e| e.into_inner());
        if Repository::open(&p).is_ok() {
            return Ok(InitResult { repo: p.to_string_lossy().into_owned(), created: false });
        }
        std::fs::create_dir_all(&p).map_err(|e| format!("cannot create '{}': {e}", p.display()))?;
        let mut o = RepositoryInitOptions::new();
        o.bare(true).initial_head("main").mkpath(true);
        Repository::init_opts(&p, &o).map_err(ge)?;
        Ok(InitResult { repo: p.to_string_lossy().into_owned(), created: true })
    })
    .await
}

/// Commit a file set. By default changes are applied on top of the parent's tree
/// (`base: "parent"`); with `base: "empty"` the commit contains only the given files.
/// Returns the new commit id.
#[tauri::command]
pub async fn snapshot_commit(
    repo: String,
    files: Vec<FileSpec>,
    message: String,
    metadata: Option<serde_json::Value>,
    tag: Option<String>,
    base: Option<String>,
) -> Result<String, String> {
    run(move || {
        let (r, p) = open_repo(&repo)?;
        let lock = repo_lock(&p);
        let _g = lock.lock().unwrap_or_else(|e| e.into_inner());

        let parent = r.head().ok().and_then(|h| h.peel_to_commit().ok());
        let mut map = match (&parent, base.as_deref()) {
            (Some(c), None) | (Some(c), Some("parent")) => flatten(&r, &c.tree().map_err(ge)?)?,
            (_, None) | (_, Some("parent")) | (_, Some("empty")) => BTreeMap::new(),
            (_, Some(o)) => return Err(format!("invalid base '{o}'")),
        };
        for f in &files {
            let path = clean_rel_path(&f.path)?;
            // Drop entries that would collide as file-vs-directory.
            let pre = format!("{path}/");
            map.retain(|k, _| k != &path && !k.starts_with(&pre) && !path.starts_with(&format!("{k}/")));
            if f.absent.unwrap_or(false) {
                continue;
            }
            let oid = if let Some(lp) = &f.local_path {
                let md = std::fs::metadata(lp).map_err(|e| format!("cannot read '{lp}': {e}"))?;
                if !md.is_file() {
                    return Err(format!("'{lp}' is not a file"));
                }
                r.blob_path(Path::new(lp)).map_err(|e| format!("cannot store '{lp}': {e}"))?
            } else if let Some(b64) = &f.content_base64 {
                if b64.len() > MAX_INLINE_BYTES * 4 / 3 + 8 {
                    return Err(format!("inline content for '{path}' exceeds {MAX_INLINE_BYTES} bytes"));
                }
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(b64.trim())
                    .map_err(|e| format!("invalid base64 for '{path}': {e}"))?;
                r.blob(&bytes).map_err(ge)?
            } else {
                return Err(format!("file '{path}': one of localPath, contentBase64 or absent is required"));
            };
            map.insert(path, (oid, 0o100644));
        }

        let tree_oid = build_tree(&r, &map)?;
        let tree = r.find_tree(tree_oid).map_err(ge)?;
        let mut msg = message.trim_end().to_string();
        if let Some(m) = &metadata {
            if !m.is_object() {
                return Err("metadata must be a JSON object".into());
            }
            msg.push_str("\n\n");
            msg.push_str(TRAILER);
            msg.push_str(&serde_json::to_string(m).map_err(ge)?);
        }
        let s = sig()?;
        let parents: Vec<&git2::Commit> = parent.iter().collect();
        let id = r.commit(Some("HEAD"), &s, &s, &msg, &tree, &parents).map_err(ge)?;
        if let Some(t) = tag.filter(|t| !t.is_empty()) {
            make_tag(&r, &t, id, true)?;
        }
        Ok(id.to_string())
    })
    .await
}

fn make_tag(r: &Repository, name: &str, id: Oid, force: bool) -> Result<(), String> {
    if !git2::Reference::is_valid_name(&format!("refs/tags/{name}")) {
        return Err(format!("invalid tag name: '{name}'"));
    }
    let obj = r.find_object(id, Some(ObjectType::Commit)).map_err(ge)?;
    r.tag_lightweight(name, &obj, force).map_err(ge)?;
    Ok(())
}

/// History, newest first. With `path`, only commits that changed that file.
#[tauri::command]
pub async fn snapshot_log(repo: String, limit: Option<usize>, path: Option<String>) -> Result<Vec<LogEntry>, String> {
    run(move || {
        let (r, _) = open_repo(&repo)?;
        let limit = limit.unwrap_or(50).clamp(1, MAX_LOG_LIMIT);
        let path = path.filter(|p| !p.is_empty()).map(|p| clean_rel_path(&p)).transpose()?;
        if r.head().is_err() {
            return Ok(vec![]);
        }
        let mut tags: HashMap<Oid, Vec<String>> = HashMap::new();
        if let Ok(names) = r.tag_names(None) {
            for i in 0..names.len() {
                let Ok(Some(n)) = names.get(i) else { continue };
                if let Ok(o) = r.revparse_single(&format!("refs/tags/{n}")).and_then(|o| o.peel_to_commit()) {
                    tags.entry(o.id()).or_default().push(n.to_string());
                }
            }
        }
        let mut w = r.revwalk().map_err(ge)?;
        w.push_head().map_err(ge)?;
        w.set_sorting(git2::Sort::TIME).map_err(ge)?;
        let mut out = Vec::new();
        for id in w {
            let id = id.map_err(ge)?;
            let c = r.find_commit(id).map_err(ge)?;
            if let Some(pa) = &path {
                let cur = blob_oid_at(&c, pa);
                let prev = c.parent(0).ok().and_then(|pc| blob_oid_at(&pc, pa));
                if cur == prev {
                    continue;
                }
            }
            let (message, metadata) = split_message(c.message().unwrap_or(""));
            let sid = id.to_string();
            out.push(LogEntry {
                short_id: sid[..8].to_string(),
                id: sid,
                message,
                metadata,
                time: c.time().seconds(),
                tags: tags.remove(&id).unwrap_or_default(),
            });
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    })
    .await
}

#[derive(Clone)]
struct Item {
    oid: Option<Oid>,
    file: Option<PathBuf>,
    size: u64,
}

fn collect_side(r: &Repository, spec: &str) -> Result<BTreeMap<String, Item>, String> {
    let mut out = BTreeMap::new();
    if let Some(dir) = spec.strip_prefix("WORKDIR:") {
        let root = PathBuf::from(dir);
        if !root.is_dir() {
            return Err(format!("'{dir}' is not a directory"));
        }
        for e in walkdir::WalkDir::new(&root).follow_links(false).sort_by_file_name() {
            let e = e.map_err(ge)?;
            if !e.file_type().is_file() {
                continue;
            }
            let rel = e.path().strip_prefix(&root).map_err(ge)?;
            let rel = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            if rel.split('/').any(|c| c.eq_ignore_ascii_case(".git")) {
                continue;
            }
            if out.len() >= MAX_WORKDIR_FILES {
                return Err(format!("WORKDIR has more than {MAX_WORKDIR_FILES} files"));
            }
            let size = e.metadata().map_err(ge)?.len();
            out.insert(rel, Item { oid: None, file: Some(e.path().to_path_buf()), size });
        }
    } else {
        let c = resolve_commit(r, spec)?;
        let t = c.tree().map_err(ge)?;
        for (k, (oid, _)) in flatten(r, &t)? {
            let size = r.find_blob(oid).map_err(ge)?.size() as u64;
            out.insert(k, Item { oid: Some(oid), file: None, size });
        }
    }
    Ok(out)
}

fn item_oid(it: &Item) -> Result<Oid, String> {
    match (&it.oid, &it.file) {
        (Some(o), _) => Ok(*o),
        (None, Some(f)) => Oid::hash_file(ObjectType::Blob, f).map_err(ge),
        _ => Err("empty item".into()),
    }
}

fn item_bytes(r: &Repository, it: &Item) -> Result<Vec<u8>, String> {
    match (&it.oid, &it.file) {
        (Some(o), _) => Ok(r.find_blob(*o).map_err(ge)?.content().to_vec()),
        (None, Some(f)) => std::fs::read(f).map_err(ge),
        _ => Ok(vec![]),
    }
}

fn is_binary(b: &[u8]) -> bool {
    b[..b.len().min(8000)].contains(&0)
}

/// Diff two sides; each is a commit-ish or `WORKDIR:<dir>`.
#[tauri::command]
pub async fn snapshot_diff(repo: String, from: String, to: String) -> Result<DiffResult, String> {
    run(move || {
        let (r, _) = open_repo(&repo)?;
        let a = collect_side(&r, &from)?;
        let b = collect_side(&r, &to)?;
        let mut keys: Vec<&String> = a.keys().chain(b.keys()).collect();
        keys.sort();
        keys.dedup();

        let mut files = Vec::new();
        let mut truncated = false;
        let mut budget = MAX_PATCH_TOTAL_BYTES;
        for k in keys {
            let (ia, ib) = (a.get(k), b.get(k));
            let status = match (ia, ib) {
                (Some(_), None) => "removed",
                (None, Some(_)) => "added",
                (Some(x), Some(y)) => {
                    if x.size == y.size && item_oid(x)? == item_oid(y)? {
                        continue;
                    }
                    "modified"
                }
                _ => continue,
            };
            if files.len() >= MAX_DIFF_FILES {
                truncated = true;
                break;
            }
            let (os, ns) = (ia.map_or(0, |i| i.size), ib.map_or(0, |i| i.size));
            let mut df = DiffFile {
                path: k.clone(),
                status: status.into(),
                binary: false,
                old_size: os,
                new_size: ns,
                patch: None,
                patch_skipped: None,
            };
            if os > MAX_PATCH_FILE_BYTES || ns > MAX_PATCH_FILE_BYTES {
                df.patch_skipped = Some("too_large".into());
            } else if budget == 0 {
                df.patch_skipped = Some("budget".into());
                truncated = true;
            } else {
                let ob = ia.map(|i| item_bytes(&r, i)).transpose()?.unwrap_or_default();
                let nb = ib.map(|i| item_bytes(&r, i)).transpose()?.unwrap_or_default();
                if is_binary(&ob) || is_binary(&nb) {
                    df.binary = true;
                } else {
                    let pa = format!("a/{k}");
                    let pb = format!("b/{k}");
                    let mut p = git2::Patch::from_buffers(
                        &ob,
                        Some(Path::new(&pa)),
                        &nb,
                        Some(Path::new(&pb)),
                        None,
                    )
                    .map_err(ge)?;
                    let buf = p.to_buf().map_err(ge)?;
                    let text = String::from_utf8_lossy(&buf).into_owned();
                    budget = budget.saturating_sub(text.len());
                    df.patch = Some(text);
                }
            }
            files.push(df);
        }
        Ok(DiffResult { files, truncated })
    })
    .await
}

/// Write `path` as it was at `commit` to `destPath`. Returns status `absent` (nothing written)
/// when the file did not exist at that commit.
#[tauri::command]
pub async fn snapshot_restore_file(
    repo: String,
    commit: String,
    path: String,
    dest_path: String,
) -> Result<RestoreResult, String> {
    run(move || {
        let (r, _) = open_repo(&repo)?;
        let path = clean_rel_path(&path)?;
        let c = resolve_commit(&r, &commit)?;
        match read_blob(&r, &c, &path)? {
            None => Ok(RestoreResult { status: "absent".into(), bytes: 0 }),
            Some(data) => {
                let d = PathBuf::from(&dest_path);
                if let Some(parent) = d.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| format!("cannot create '{}': {e}", parent.display()))?;
                }
                std::fs::write(&d, &data).map_err(|e| format!("cannot write '{dest_path}': {e}"))?;
                Ok(RestoreResult { status: "restored".into(), bytes: data.len() as u64 })
            }
        }
    })
    .await
}

#[tauri::command]
pub async fn snapshot_list_files(repo: String, commit: String) -> Result<Vec<FileInfo>, String> {
    run(move || {
        let (r, _) = open_repo(&repo)?;
        let c = resolve_commit(&r, &commit)?;
        let t = c.tree().map_err(ge)?;
        let mut out = Vec::new();
        for (path, (oid, _)) in flatten(&r, &t)? {
            let size = r.find_blob(oid).map_err(ge)?.size() as u64;
            out.push(FileInfo { path, size });
        }
        Ok(out)
    })
    .await
}

/// Create/move a lightweight tag on a commit (`force` default true).
#[tauri::command]
pub async fn snapshot_tag(repo: String, name: String, commit: String, force: Option<bool>) -> Result<(), String> {
    run(move || {
        let (r, p) = open_repo(&repo)?;
        let lock = repo_lock(&p);
        let _g = lock.lock().unwrap_or_else(|e| e.into_inner());
        let c = resolve_commit(&r, &commit)?;
        make_tag(&r, &name, c.id(), force.unwrap_or(true))
    })
    .await
}

#[tauri::command]
pub async fn snapshot_list_tags(repo: String) -> Result<Vec<TagInfo>, String> {
    run(move || {
        let (r, _) = open_repo(&repo)?;
        let mut out = Vec::new();
        let names = r.tag_names(None).map_err(ge)?;
        for i in 0..names.len() {
            let Ok(Some(n)) = names.get(i) else { continue };
            if let Ok(c) = r.revparse_single(&format!("refs/tags/{n}")).and_then(|o| o.peel_to_commit()) {
                out.push(TagInfo { name: n.to_string(), commit_id: c.id().to_string() });
            }
        }
        Ok(out)
    })
    .await
}

/// Read a file at a commit (base64, capped by `maxBytes`, hard cap 32 MiB).
#[tauri::command]
pub async fn snapshot_read_file(
    repo: String,
    commit: String,
    path: String,
    max_bytes: Option<u64>,
) -> Result<ReadResult, String> {
    run(move || {
        let (r, _) = open_repo(&repo)?;
        let path = clean_rel_path(&path)?;
        let c = resolve_commit(&r, &commit)?;
        let cap = max_bytes.unwrap_or(1024 * 1024).min(MAX_READ_BYTES) as usize;
        Ok(match read_blob(&r, &c, &path)? {
            None => ReadResult { absent: true, size: 0, truncated: false, binary: false, content_base64: String::new() },
            Some(d) => {
                let size = d.len() as u64;
                let part = &d[..d.len().min(cap)];
                ReadResult {
                    absent: false,
                    size,
                    truncated: part.len() < d.len(),
                    binary: is_binary(part),
                    content_base64: base64::engine::general_purpose::STANDARD.encode(part),
                }
            }
        })
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("target").join("test-scratch").join(name);
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn rel_path_checks() {
        assert!(clean_rel_path("a/b.txt").is_ok());
        assert!(clean_rel_path("../x").is_err());
        assert!(clean_rel_path("/x").is_err());
        assert!(clean_rel_path("a/../x").is_err());
        assert!(clean_rel_path("Z:/x").is_err());
        assert!(clean_rel_path("a/.git/x").is_err());
        assert_eq!(clean_rel_path("a\\b").unwrap(), "a/b");
    }

    #[tokio::test]
    async fn commit_diff_restore() {
        let root = scratch("snapshot_flow");
        let repo = root.join("repo").to_string_lossy().into_owned();
        let src = root.join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("f.txt"), "hello\n").unwrap();
        let init = snapshot_init(Some(repo.clone()), None).await.unwrap();
        assert!(init.created);

        let c1 = snapshot_commit(
            repo.clone(),
            vec![
                FileSpec { path: "dir/f.txt".into(), local_path: Some(src.join("f.txt").to_string_lossy().into_owned()), content_base64: None, absent: None },
                FileSpec { path: "گزارش.txt".into(), local_path: None, content_base64: Some(base64::engine::general_purpose::STANDARD.encode("سلام")), absent: None },
                FileSpec { path: "new.txt".into(), local_path: None, content_base64: None, absent: Some(true) },
            ],
            "first".into(),
            Some(serde_json::json!({"session":"s1"})),
            Some("v1".into()),
            None,
        )
        .await
        .unwrap();

        std::fs::write(src.join("f.txt"), "hello\nworld\n").unwrap();
        let d = snapshot_diff(repo.clone(), c1.clone(), format!("WORKDIR:{}", src.to_string_lossy())).await.unwrap();
        assert!(d.files.iter().any(|f| f.status == "removed" && f.path == "dir/f.txt"));

        let log = snapshot_log(repo.clone(), Some(10), None).await.unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].metadata.as_ref().unwrap()["session"], "s1");
        assert_eq!(log[0].message, "first");

        let out = root.join("out").join("r.txt");
        let r = snapshot_restore_file(repo.clone(), "v1".into(), "dir/f.txt".into(), out.to_string_lossy().into_owned()).await.unwrap();
        assert_eq!(r.status, "restored");
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "hello\n");
        let r = snapshot_restore_file(repo.clone(), c1, "new.txt".into(), out.to_string_lossy().into_owned()).await.unwrap();
        assert_eq!(r.status, "absent");
        assert!(snapshot_restore_file(repo.clone(), "v1".into(), "../x".into(), "x".into()).await.is_err());
        assert_eq!(snapshot_list_tags(repo).await.unwrap().len(), 1);
    }
}
