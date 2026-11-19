//! Filesystem utilities: hashing, tree manifests/compare, zip create/extract (zip-slip safe).
//!
//! Long operations emit `fsutil://progress` `{op_id, done, total, phase}` (bytes) and can be
//! cancelled with `fs_cancel(opId)`. All relative paths in outputs use `/` and UTF-8.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter};

const MAX_TREE_FILES: usize = 500_000;
const MAX_ZIP_ENTRIES: usize = 100_000;
const DEFAULT_MAX_EXTRACT_BYTES: u64 = 10 * 1024 * 1024 * 1024;
const MAX_RATIO: u64 = 1000;
const RATIO_MIN_SIZE: u64 = 64 * 1024 * 1024;
const PROGRESS_EVENT: &str = "fsutil://progress";

// ---------------------------------------------------------------- op registry / progress

fn registry() -> &'static Mutex<HashMap<String, Arc<AtomicBool>>> {
    static R: OnceLock<Mutex<HashMap<String, Arc<AtomicBool>>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(HashMap::new()))
}

fn gen_id() -> String {
    use std::sync::atomic::AtomicU64;
    static N: AtomicU64 = AtomicU64::new(0);
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
    format!("op-{t}-{}", N.fetch_add(1, Ordering::Relaxed))
}

struct Op {
    id: String,
    cancel: Arc<AtomicBool>,
    app: Option<AppHandle>,
    last: Instant,
    done: u64,
    total: u64,
}

impl Op {
    fn new(app: Option<AppHandle>, op_id: Option<String>) -> Op {
        let id = op_id.filter(|s| !s.is_empty()).unwrap_or_else(|| gen_id());
        let cancel = Arc::new(AtomicBool::new(false));
        registry().lock().unwrap_or_else(|e| e.into_inner()).insert(id.clone(), cancel.clone());
        Op { id, cancel, app, last: Instant::now() - Duration::from_secs(1), done: 0, total: 0 }
    }
    fn check(&self) -> Result<(), String> {
        if self.cancel.load(Ordering::Relaxed) {
            Err("cancelled".into())
        } else {
            Ok(())
        }
    }
    fn emit(&mut self, phase: &str, force: bool) {
        if !force && self.last.elapsed() < Duration::from_millis(100) {
            return;
        }
        self.last = Instant::now();
        if let Some(a) = &self.app {
            let _ = a.emit(
                PROGRESS_EVENT,
                serde_json::json!({"op_id": self.id, "done": self.done, "total": self.total, "phase": phase}),
            );
        }
    }
    fn add(&mut self, n: u64, phase: &str) -> Result<(), String> {
        self.done += n;
        self.check()?;
        self.emit(phase, false);
        Ok(())
    }
}

impl Drop for Op {
    fn drop(&mut self) {
        registry().lock().unwrap_or_else(|e| e.into_inner()).remove(&self.id);
    }
}

/// Request cancellation of a running operation. Returns whether the op was found.
#[tauri::command]
pub async fn fs_cancel(op_id: String) -> Result<bool, String> {
    let g = registry().lock().unwrap_or_else(|e| e.into_inner());
    Ok(match g.get(&op_id) {
        Some(f) => {
            f.store(true, Ordering::Relaxed);
            true
        }
        None => false,
    })
}

async fn run<T: Send + 'static>(f: impl FnOnce() -> Result<T, String> + Send + 'static) -> Result<T, String> {
    tokio::task::spawn_blocking(f).await.map_err(|e| format!("task failed: {e}"))?
}

fn ge<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

// ---------------------------------------------------------------- globs / walking

/// Glob matcher where each pattern also matches at any depth and as a directory prefix
/// (so `node_modules` or `*.log` behave like gitignore-style names).
struct Globs(Option<GlobSet>);

impl Globs {
    fn new(patterns: &[String]) -> Result<Globs, String> {
        if patterns.is_empty() {
            return Ok(Globs(None));
        }
        let mut b = GlobSetBuilder::new();
        for p in patterns {
            let p = p.replace('\\', "/");
            let p = p.trim_start_matches("./").trim_end_matches('/');
            if p.is_empty() {
                continue;
            }
            for v in [p.to_string(), format!("**/{p}"), format!("{p}/**"), format!("**/{p}/**")] {
                b.add(Glob::new(&v).map_err(|e| format!("bad glob '{p}': {e}"))?);
            }
        }
        Ok(Globs(Some(b.build().map_err(ge)?)))
    }
    fn is_match(&self, rel: &str) -> bool {
        self.0.as_ref().map_or(false, |s| s.is_match(rel))
    }
    fn is_empty(&self) -> bool {
        self.0.is_none()
    }
}

fn rel_string(root: &Path, p: &Path) -> Result<String, String> {
    let rel = p.strip_prefix(root).map_err(ge)?;
    Ok(rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect::<Vec<_>>().join("/"))
}

struct FileItem {
    rel: String,
    abs: PathBuf,
    size: u64,
    is_dir_empty: bool,
}

/// Walk `root`, skipping ignored paths (dirs are pruned). `include` (if non-empty) filters files.
fn walk(
    root: &Path,
    ignore: &Globs,
    include: &Globs,
    follow_symlinks: bool,
    want_empty_dirs: bool,
    op: &Op,
) -> Result<Vec<FileItem>, String> {
    if !root.is_dir() {
        return Err(format!("'{}' is not a directory", root.display()));
    }
    let mut out = Vec::new();
    let it = walkdir::WalkDir::new(root).follow_links(follow_symlinks).sort_by_file_name().into_iter();
    let it = it.filter_entry(|e| {
        if e.depth() == 0 {
            return true;
        }
        match rel_string(root, e.path()) {
            Ok(rel) => !ignore.is_match(&rel),
            Err(_) => false,
        }
    });
    for e in it {
        op.check()?;
        let e = e.map_err(ge)?;
        if e.depth() == 0 {
            continue;
        }
        let rel = rel_string(root, e.path())?;
        let ft = e.file_type();
        if ft.is_file() {
            if !include.is_empty() && !include.is_match(&rel) {
                continue;
            }
            if out.len() >= MAX_TREE_FILES {
                return Err(format!("more than {MAX_TREE_FILES} files"));
            }
            out.push(FileItem { rel, abs: e.path().to_path_buf(), size: e.metadata().map_err(ge)?.len(), is_dir_empty: false });
        } else if ft.is_dir() && want_empty_dirs {
            let empty = std::fs::read_dir(e.path()).map_err(ge)?.next().is_none();
            if empty && (include.is_empty() || include.is_match(&rel)) {
                out.push(FileItem { rel, abs: e.path().to_path_buf(), size: 0, is_dir_empty: true });
            }
        }
    }
    Ok(out)
}

fn hash_path(p: &Path, op: &mut Op, phase: &str) -> Result<String, String> {
    let mut f = File::open(p).map_err(|e| format!("cannot open '{}': {e}", p.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|e| format!("read error '{}': {e}", p.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        op.add(n as u64, phase)?;
    }
    Ok(hex::encode(h.finalize()))
}

fn check_algo(algo: &Option<String>) -> Result<(), String> {
    match algo.as_deref().map(|a| a.to_ascii_lowercase().replace('-', "")) {
        None => Ok(()),
        Some(a) if a == "sha256" => Ok(()),
        Some(a) => Err(format!("unsupported algo '{a}' (only sha256)")),
    }
}

// ---------------------------------------------------------------- hashing

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HashFileResult {
    pub path: String,
    pub size: u64,
    pub algo: String,
    pub hash: String,
}

#[tauri::command]
pub async fn fs_hash_file(
    app: AppHandle,
    path: String,
    algo: Option<String>,
    op_id: Option<String>,
) -> Result<HashFileResult, String> {
    check_algo(&algo)?;
    run(move || {
        let mut op = Op::new(Some(app), op_id);
        let size = std::fs::metadata(&path).map_err(|e| format!("cannot stat '{path}': {e}"))?.len();
        op.total = size;
        let hash = hash_path(Path::new(&path), &mut op, "hash")?;
        op.emit("hash", true);
        Ok(HashFileResult { path, size, algo: "sha256".into(), hash })
    })
    .await
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ManifestEntry {
    pub rel_path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeHashResult {
    pub root: String,
    pub entries: Vec<ManifestEntry>,
    pub tree_hash: String,
    pub file_count: usize,
    pub total_size: u64,
}

fn tree_hash_of(entries: &[ManifestEntry]) -> String {
    let mut h = Sha256::new();
    for e in entries {
        h.update(e.rel_path.as_bytes());
        h.update([0u8]);
        h.update(e.size.to_string().as_bytes());
        h.update([0u8]);
        h.update(e.sha256.as_bytes());
        h.update([b'\n']);
    }
    hex::encode(h.finalize())
}

fn build_manifest(root: &str, ignore: &[String], follow: bool, op: &mut Op) -> Result<Vec<ManifestEntry>, String> {
    let ig = Globs::new(ignore)?;
    let files = walk(Path::new(root), &ig, &Globs(None), follow, false, op)?;
    op.total += files.iter().map(|f| f.size).sum::<u64>();
    let mut out = Vec::with_capacity(files.len());
    for f in files {
        let sha256 = hash_path(&f.abs, op, "hash")?;
        out.push(ManifestEntry { rel_path: f.rel, size: f.size, sha256 });
    }
    out.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    Ok(out)
}

#[tauri::command]
pub async fn fs_hash_tree(
    app: AppHandle,
    root: String,
    ignore: Option<Vec<String>>,
    follow_symlinks: Option<bool>,
    op_id: Option<String>,
) -> Result<TreeHashResult, String> {
    run(move || {
        let mut op = Op::new(Some(app), op_id);
        let entries = build_manifest(&root, &ignore.unwrap_or_default(), follow_symlinks.unwrap_or(false), &mut op)?;
        op.emit("hash", true);
        let total_size = entries.iter().map(|e| e.size).sum();
        Ok(TreeHashResult { root, tree_hash: tree_hash_of(&entries), file_count: entries.len(), total_size, entries })
    })
    .await
}

// ---------------------------------------------------------------- compare

/// A tree is a directory path, a manifest array, or `{entries: [...]}`.
#[derive(Deserialize)]
#[serde(untagged)]
pub enum TreeInput {
    Path(String),
    Entries(Vec<ManifestEntry>),
    Manifest { entries: Vec<ManifestEntry> },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModifiedEntry {
    pub rel_path: String,
    pub a_size: u64,
    pub b_size: u64,
    pub a_sha256: String,
    pub b_sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompareResult {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub modified: Vec<ModifiedEntry>,
    pub same: Vec<String>,
}

fn load_tree(t: TreeInput, ignore: &[String], op: &mut Op) -> Result<BTreeMap<String, ManifestEntry>, String> {
    let v = match t {
        TreeInput::Path(p) => build_manifest(&p, ignore, false, op)?,
        TreeInput::Entries(v) | TreeInput::Manifest { entries: v } => v,
    };
    Ok(v.into_iter().map(|e| (e.rel_path.replace('\\', "/"), e)).collect())
}

/// `a` is the baseline ("old"), `b` the new side: files only in `b` are `added`.
#[tauri::command]
pub async fn fs_compare_trees(
    app: AppHandle,
    a: TreeInput,
    b: TreeInput,
    ignore: Option<Vec<String>>,
    op_id: Option<String>,
) -> Result<CompareResult, String> {
    run(move || {
        let ig = ignore.unwrap_or_default();
        let mut op = Op::new(Some(app), op_id);
        let ma = load_tree(a, &ig, &mut op)?;
        let mb = load_tree(b, &ig, &mut op)?;
        op.emit("compare", true);
        let mut r = CompareResult { added: vec![], removed: vec![], modified: vec![], same: vec![] };
        for (k, ea) in &ma {
            match mb.get(k) {
                None => r.removed.push(k.clone()),
                Some(eb) if eb.sha256 == ea.sha256 && eb.size == ea.size => r.same.push(k.clone()),
                Some(eb) => r.modified.push(ModifiedEntry {
                    rel_path: k.clone(),
                    a_size: ea.size,
                    b_size: eb.size,
                    a_sha256: ea.sha256.clone(),
                    b_sha256: eb.sha256.clone(),
                }),
            }
        }
        r.added = mb.keys().filter(|k| !ma.contains_key(*k)).cloned().collect();
        Ok(r)
    })
    .await
}

// ---------------------------------------------------------------- zip create

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZipCreateResult {
    pub op_id: String,
    pub dest_zip: String,
    pub file_count: usize,
    pub total_bytes: u64,
    pub zip_bytes: u64,
}

#[tauri::command]
pub async fn zip_create(
    app: AppHandle,
    src_root: String,
    dest_zip: String,
    include: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
    level: Option<i64>,
    op_id: Option<String>,
) -> Result<ZipCreateResult, String> {
    run(move || {
        let mut op = Op::new(Some(app), op_id);
        let level = level.unwrap_or(6).clamp(0, 9);
        let root = PathBuf::from(&src_root);
        let ig = Globs::new(&exclude.unwrap_or_default())?;
        let inc = Globs::new(&include.unwrap_or_default())?;
        let dest = PathBuf::from(&dest_zip);
        let dest_canon = dest.parent().and_then(|p| p.canonicalize().ok()).map(|p| p.join(dest.file_name().unwrap_or_default()));
        let mut files = walk(&root, &ig, &inc, false, true, &op)?;
        files.retain(|f| {
            let abs = f.abs.canonicalize().ok();
            !(abs.is_some() && abs == dest_canon)
        });
        op.total = files.iter().map(|f| f.size).sum();
        if let Some(p) = dest.parent() {
            std::fs::create_dir_all(p).map_err(|e| format!("cannot create '{}': {e}", p.display()))?;
        }
        let part = PathBuf::from(format!("{dest_zip}.part"));
        let res = (|| -> Result<(usize, u64), String> {
            let w = BufWriter::new(File::create(&part).map_err(|e| format!("cannot create '{}': {e}", part.display()))?);
            let mut zw = zip::ZipWriter::new(w);
            let method = if level == 0 { zip::CompressionMethod::Stored } else { zip::CompressionMethod::Deflated };
            let mut count = 0usize;
            let mut total = 0u64;
            let mut buf = vec![0u8; 256 * 1024];
            for f in &files {
                op.check()?;
                if f.is_dir_empty {
                    zw.add_directory(format!("{}/", f.rel), zip::write::SimpleFileOptions::default()).map_err(ge)?;
                    continue;
                }
                let mut opts = zip::write::SimpleFileOptions::default()
                    .compression_method(method)
                    .large_file(f.size > 3 * 1024 * 1024 * 1024);
                if level > 0 {
                    opts = opts.compression_level(Some(level));
                }
                zw.start_file(f.rel.as_str(), opts).map_err(ge)?;
                let mut rd = File::open(&f.abs).map_err(|e| format!("cannot open '{}': {e}", f.abs.display()))?;
                loop {
                    let n = rd.read(&mut buf).map_err(ge)?;
                    if n == 0 {
                        break;
                    }
                    zw.write_all(&buf[..n]).map_err(ge)?;
                    total += n as u64;
                    op.add(n as u64, "zip")?;
                }
                count += 1;
            }
            zw.finish().map_err(ge)?.flush().map_err(ge)?;
            Ok((count, total))
        })();
        match res {
            Ok((file_count, total_bytes)) => {
                let _ = std::fs::remove_file(&dest);
                std::fs::rename(&part, &dest).map_err(|e| format!("cannot finalize '{dest_zip}': {e}"))?;
                let zip_bytes = std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
                op.emit("zip", true);
                Ok(ZipCreateResult { op_id: op.id.clone(), dest_zip, file_count, total_bytes, zip_bytes })
            }
            Err(e) => {
                let _ = std::fs::remove_file(&part);
                Err(e)
            }
        }
    })
    .await
}

// ---------------------------------------------------------------- zip extract

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZipExtractResult {
    pub op_id: String,
    pub dest_dir: String,
    pub files: usize,
    pub dirs: usize,
    pub total_bytes: u64,
    pub skipped_symlinks: usize,
}

/// Validate a zip entry name into safe relative components.
fn safe_components(name: &str) -> Result<Vec<String>, String> {
    let n = name.replace('\\', "/");
    if n.contains('\0') || n.starts_with('/') {
        return Err(format!("unsafe zip entry path: '{name}'"));
    }
    let mut out = Vec::new();
    for c in n.split('/') {
        if c.is_empty() || c == "." {
            continue;
        }
        if c == ".." || c.contains(':') {
            return Err(format!("unsafe zip entry path: '{name}'"));
        }
        out.push(c.to_string());
    }
    Ok(out)
}

/// Create the directory chain `dest/comps[..n]`, refusing to pass through symlinks/junctions.
fn ensure_dirs(dest: &Path, comps: &[String]) -> Result<PathBuf, String> {
    let mut cur = dest.to_path_buf();
    for c in comps {
        cur.push(c);
        match std::fs::symlink_metadata(&cur) {
            Ok(m) => {
                if m.file_type().is_symlink() {
                    return Err(format!("zip entry passes through a symlink: '{}'", cur.display()));
                }
                if !m.is_dir() {
                    return Err(format!("zip entry collides with a file: '{}'", cur.display()));
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    // FILE_ATTRIBUTE_REPARSE_POINT (junctions, mount points)
                    if m.file_attributes() & 0x400 != 0 {
                        return Err(format!("zip entry passes through a reparse point: '{}'", cur.display()));
                    }
                }
            }
            Err(_) => std::fs::create_dir(&cur).map_err(|e| format!("cannot create '{}': {e}", cur.display()))?,
        }
    }
    Ok(cur)
}

#[tauri::command]
pub async fn zip_extract(
    app: AppHandle,
    zip: String,
    dest_dir: String,
    overwrite: Option<bool>,
    max_total_bytes: Option<u64>,
    max_entries: Option<usize>,
    op_id: Option<String>,
) -> Result<ZipExtractResult, String> {
    run(move || {
        let mut op = Op::new(Some(app), op_id);
        let overwrite = overwrite.unwrap_or(false);
        let max_total = max_total_bytes.unwrap_or(DEFAULT_MAX_EXTRACT_BYTES).min(DEFAULT_MAX_EXTRACT_BYTES * 10);
        let max_entries = max_entries.unwrap_or(MAX_ZIP_ENTRIES).min(MAX_ZIP_ENTRIES * 10);
        let dest = PathBuf::from(&dest_dir);
        let f = File::open(&zip).map_err(|e| format!("cannot open '{zip}': {e}"))?;
        let mut ar = zip::ZipArchive::new(BufReader::new(f)).map_err(|e| format!("invalid zip: {e}"))?;
        if ar.len() > max_entries {
            return Err(format!("zip has {} entries (limit {max_entries})", ar.len()));
        }

        // Pre-pass: validate every entry before touching the disk.
        let mut declared = 0u64;
        for i in 0..ar.len() {
            let e = ar.by_index_raw(i).map_err(ge)?;
            let ename = e.name().map_err(ge)?.into_owned();
            let comps = safe_components(&ename)?;
            if e.is_dir() || comps.is_empty() {
                continue;
            }
            if e.is_symlink() {
                continue;
            }
            declared = declared.saturating_add(e.size());
            if declared > max_total {
                return Err(format!("zip expands to more than {max_total} bytes"));
            }
            if e.size() > RATIO_MIN_SIZE && e.compressed_size() > 0 && e.size() / e.compressed_size() > MAX_RATIO {
                return Err(format!("suspicious compression ratio for '{ename}'"));
            }
            if !overwrite {
                let target = comps.iter().fold(dest.clone(), |p, c| p.join(c));
                if target.exists() {
                    return Err(format!("'{}' already exists (overwrite=false)", target.display()));
                }
            }
        }
        op.total = declared;
        std::fs::create_dir_all(&dest).map_err(|e| format!("cannot create '{dest_dir}': {e}"))?;

        let (mut files, mut dirs, mut skipped, mut written_total) = (0usize, 0usize, 0usize, 0u64);
        let mut buf = vec![0u8; 256 * 1024];
        for i in 0..ar.len() {
            op.check()?;
            let mut e = ar.by_index(i).map_err(ge)?;
            let ename = e.name().map_err(ge)?.into_owned();
            let comps = safe_components(&ename)?;
            if comps.is_empty() {
                continue;
            }
            if e.is_symlink() {
                skipped += 1;
                continue;
            }
            if e.is_dir() {
                ensure_dirs(&dest, &comps)?;
                dirs += 1;
                continue;
            }
            let parent = ensure_dirs(&dest, &comps[..comps.len() - 1])?;
            let target = parent.join(&comps[comps.len() - 1]);
            if let Ok(m) = std::fs::symlink_metadata(&target) {
                if m.file_type().is_symlink() || m.is_dir() {
                    return Err(format!("cannot overwrite '{}'", target.display()));
                }
            }
            let mut out = BufWriter::new(File::create(&target).map_err(|er| format!("cannot create '{}': {er}", target.display()))?);
            let res = (|| -> Result<(), String> {
                loop {
                    let n = e.read(&mut buf).map_err(ge)?;
                    if n == 0 {
                        break;
                    }
                    written_total += n as u64;
                    if written_total > max_total {
                        return Err(format!("zip expands to more than {max_total} bytes"));
                    }
                    out.write_all(&buf[..n]).map_err(ge)?;
                    op.add(n as u64, "extract")?;
                }
                out.flush().map_err(ge)
            })();
            if let Err(er) = res {
                drop(out);
                let _ = std::fs::remove_file(&target);
                return Err(er);
            }
            files += 1;
        }
        op.emit("extract", true);
        Ok(ZipExtractResult { op_id: op.id.clone(), dest_dir, files, dirs, total_bytes: written_total, skipped_symlinks: skipped })
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
    fn component_checks() {
        assert!(safe_components("a/b.txt").is_ok());
        assert!(safe_components("../x").is_err());
        assert!(safe_components("a/../../x").is_err());
        assert!(safe_components("/etc/x").is_err());
        assert!(safe_components("Z:/x").is_err());
        assert!(safe_components("a/x:stream").is_err());
        assert_eq!(safe_components("پوشه\\فایل.txt").unwrap(), vec!["پوشه", "فایل.txt"]);
    }

    #[test]
    fn zip_roundtrip_and_slip() {
        let root = scratch("fsutil_zip");
        let src = root.join("src");
        std::fs::create_dir_all(src.join("پوشه")).unwrap();
        std::fs::write(src.join("پوشه").join("فایل.txt"), "سلام").unwrap();
        std::fs::write(src.join("a.log"), "x").unwrap();
        let mut op = Op::new(None, None);
        let ig = Globs::new(&["*.log".to_string()]).unwrap();
        let files = walk(&src, &ig, &Globs(None), false, false, &op).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].rel, "پوشه/فایل.txt");
        let h = hash_path(&files[0].abs, &mut op, "t").unwrap();
        assert_eq!(h.len(), 64);

        // Malicious zip with a ../ entry must be rejected by the name check.
        let evil = root.join("evil.zip");
        {
            let mut zw = zip::ZipWriter::new(File::create(&evil).unwrap());
            zw.start_file("../evil.txt", zip::write::SimpleFileOptions::default()).unwrap();
            zw.write_all(b"x").unwrap();
            zw.finish().unwrap();
        }
        let mut ar = zip::ZipArchive::new(File::open(&evil).unwrap()).unwrap();
        let e = ar.by_index_raw(0).unwrap();
        assert!(safe_components(&e.name().unwrap()).is_err());
    }
}
