//! Local file-manager operations: list, mkdir, rename, copy, delete (Recycle Bin by default).
//!
//! IPC: `fs_list_drives`, `fs_list_dir`, `fs_mkdir`, `fs_rename`, `fs_copy`, `fs_delete`.
//! Same security model as `fsio` (absolute drive paths, no UNC/device/`..`, symlinks/junctions never
//! followed or created, system folders and `nora-data` write-protected, `nora-data/vault` unreadable)
//! plus: the app's own folder (and any of its parents) can never be deleted or renamed, drive roots and
//! top-level system folders are untouchable, and every change is written to the audit log (source "fs").
//! Zero C-Drive: copy writes its temp file beside the target; Recycle Bin deletion uses the shell's
//! per-drive `$Recycle.Bin`, nothing is written to AppData/Temp by this module.
//! Progress/cancel are shared with fsutil: event `fsutil://progress` `{op_id, done, total, phase:"copy"}`
//! and `fs_cancel(opId)`.

use crate::commands::fsio::{
    check_read_allowed, check_write_allowed, ensure_no_links, mtime_ms, strip_verbatim, under, validate_path,
};
use crate::commands::fsutil::Op;
use crate::commands::terminal::audit::{self, AuditVerdict, Source};
use serde::Serialize;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tauri::AppHandle;
use walkdir::WalkDir;

const DEFAULT_LIST_MAX: usize = 20_000;
const HARD_LIST_MAX: usize = 100_000;
const COPY_CHUNK: usize = 1024 * 1024;

fn run_blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, String> + Send + 'static) -> impl std::future::Future<Output = Result<T, String>> {
    async move { tokio::task::spawn_blocking(f).await.map_err(|e| format!("task failed: {e}"))? }
}

fn audit_result<T>(label: &Option<String>, line: String, res: &Result<T, String>) {
    let who = label.clone().unwrap_or_else(|| "ui".into());
    match res {
        Ok(_) => audit::record("fs", &who, Source::Fs, &line, AuditVerdict::Allow, None),
        Err(e) => {
            let code = e.split(':').next().unwrap_or("ERROR").to_string();
            audit::record("fs", &who, Source::Fs, &line, AuditVerdict::Deny, Some(&code));
        }
    }
}

fn io_err(e: std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::NotFound => format!("NOT_FOUND: {e}"),
        std::io::ErrorKind::AlreadyExists => format!("EXISTS: {e}"),
        std::io::ErrorKind::PermissionDenied => format!("FORBIDDEN: {e}"),
        _ => format!("INVALID: {e}"),
    }
}

/// The application's own folder and every parent of it must never be removed or moved.
fn protects_app_dir(path: &Path) -> bool {
    match crate::portable::exe_dir() {
        Ok(exe) => under(&exe, path),
        Err(_) => false,
    }
}

fn is_drive_root(path: &Path) -> bool {
    path.to_string_lossy().trim_end_matches('\\').len() <= 2
}

// ---------- drives ----------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DriveInfo {
    pub letter: String,
    /// "D:/"
    pub path: String,
    /// fixed | removable | network | cdrom | ramdisk | unknown
    pub kind: String,
}

#[cfg(windows)]
fn drive_kind(letter: char) -> &'static str {
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
    let wide: Vec<u16> = format!("{letter}:\\").encode_utf16().chain(std::iter::once(0)).collect();
    match unsafe { GetDriveTypeW(wide.as_ptr()) } {
        2 => "removable",
        3 => "fixed",
        4 => "network",
        5 => "cdrom",
        6 => "ramdisk",
        _ => "unknown",
    }
}

#[cfg(windows)]
fn list_drives_impl() -> Vec<DriveInfo> {
    use windows_sys::Win32::Storage::FileSystem::GetLogicalDrives;
    let mask = unsafe { GetLogicalDrives() };
    (0..26u32)
        .filter(|i| mask & (1 << i) != 0)
        .map(|i| {
            let l = (b'A' + i as u8) as char;
            DriveInfo { letter: l.to_string(), path: format!("{l}:/"), kind: drive_kind(l).to_string() }
        })
        .collect()
}

#[cfg(not(windows))]
fn list_drives_impl() -> Vec<DriveInfo> {
    Vec::new()
}

#[cfg(windows)]
fn has_recycle_bin(path: &Path) -> bool {
    path.to_string_lossy().chars().next().map(|c| drive_kind(c.to_ascii_uppercase()) == "fixed").unwrap_or(false)
}
#[cfg(not(windows))]
fn has_recycle_bin(_path: &Path) -> bool {
    true
}

#[tauri::command]
pub async fn fs_list_drives() -> Result<Vec<DriveInfo>, String> {
    Ok(list_drives_impl())
}

// ---------- list ----------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DirEntryInfo {
    pub name: String,
    pub is_dir: bool,
    /// Symlink/junction: listed but never followed (size 0).
    pub is_symlink: bool,
    pub size: u64,
    /// ms since epoch
    pub mtime: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListDirResult {
    /// Folders first, then files; case-insensitive by name.
    pub entries: Vec<DirEntryInfo>,
    /// True when `maxEntries` was reached; narrow the folder or raise the limit.
    pub truncated: bool,
}

fn list_dir_impl(path: &str, max: Option<usize>) -> Result<ListDirResult, String> {
    let p = validate_path(path)?;
    check_read_allowed(&p)?;
    let meta = fs::symlink_metadata(&p).map_err(io_err)?;
    if meta.file_type().is_symlink() {
        return Err("FORBIDDEN: symlinks are not followed".into());
    }
    if !meta.is_dir() {
        return Err("NOT_FILE: path is not a folder".into());
    }
    ensure_no_links(&p)?;
    let limit = max.unwrap_or(DEFAULT_LIST_MAX).min(HARD_LIST_MAX);
    let mut entries = Vec::new();
    let mut truncated = false;
    for item in fs::read_dir(&p).map_err(io_err)? {
        let item = match item {
            Ok(i) => i,
            Err(_) => continue,
        };
        if entries.len() >= limit {
            truncated = true;
            break;
        }
        let m = match item.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let sym = m.file_type().is_symlink();
        entries.push(DirEntryInfo {
            name: item.file_name().to_string_lossy().to_string(),
            is_dir: !sym && m.is_dir(),
            is_symlink: sym,
            size: if m.is_file() { m.len() } else { 0 },
            mtime: mtime_ms(&m),
        });
    }
    entries.sort_by(|a, b| {
        b.is_dir.cmp(&a.is_dir).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(ListDirResult { entries, truncated })
}

#[tauri::command]
pub async fn fs_list_dir(path: String, max_entries: Option<usize>) -> Result<ListDirResult, String> {
    run_blocking(move || list_dir_impl(&path, max_entries)).await
}

// ---------- mkdir ----------

fn mkdir_impl(path: &str, recursive: bool) -> Result<(), String> {
    let p = validate_path(path)?;
    check_write_allowed(&p)?;
    if is_drive_root(&p) {
        return Err("FORBIDDEN: drive root".into());
    }
    match fs::symlink_metadata(&p) {
        Ok(m) => {
            if m.is_dir() && !m.file_type().is_symlink() && recursive {
                ensure_no_links(&p)?;
                return Ok(());
            }
            return Err(format!("EXISTS: '{}' already exists", p.display()));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_err(e)),
    }
    // Nearest existing ancestor must be a real folder (no links).
    let mut anc = p.parent().map(Path::to_path_buf);
    while let Some(a) = anc.clone() {
        if fs::symlink_metadata(&a).is_ok() {
            break;
        }
        anc = a.parent().map(Path::to_path_buf);
    }
    let anc = anc.ok_or("NOT_FOUND: no existing parent")?;
    let am = fs::symlink_metadata(&anc).map_err(io_err)?;
    if !am.is_dir() || am.file_type().is_symlink() {
        return Err("INVALID: parent is not a regular folder".into());
    }
    ensure_no_links(&anc)?;
    if !recursive && p.parent() != Some(anc.as_path()) {
        return Err("NOT_FOUND: parent folder does not exist (use recursive)".into());
    }
    if recursive { fs::create_dir_all(&p) } else { fs::create_dir(&p) }.map_err(io_err)
}

#[tauri::command]
pub async fn fs_mkdir(path: String, recursive: Option<bool>, user_label: Option<String>) -> Result<(), String> {
    let line = format!("mkdir {path}");
    let res = run_blocking(move || mkdir_impl(&path, recursive.unwrap_or(false))).await;
    audit_result(&user_label, line, &res);
    res
}

// ---------- rename / move ----------

fn rename_impl(from: &str, to: &str) -> Result<(), String> {
    let f = validate_path(from)?;
    let t = validate_path(to)?;
    check_write_allowed(&f)?;
    check_write_allowed(&t)?;
    if is_drive_root(&f) || is_drive_root(&t) {
        return Err("FORBIDDEN: drive root".into());
    }
    if protects_app_dir(&f) {
        return Err("FORBIDDEN: the application folder cannot be moved".into());
    }
    if f.to_string_lossy()[..1].to_ascii_lowercase() != t.to_string_lossy()[..1].to_ascii_lowercase() {
        return Err("INVALID: rename works within one drive; use copy + delete across drives".into());
    }
    let fm = fs::symlink_metadata(&f).map_err(io_err)?;
    if fm.file_type().is_symlink() {
        return Err("FORBIDDEN: symlinks are not followed".into());
    }
    ensure_no_links(&f)?;
    if fs::symlink_metadata(&t).is_ok() {
        return Err(format!("EXISTS: '{}' already exists", t.display()));
    }
    if fm.is_dir() && under(&t, &f) {
        return Err("INVALID: cannot move a folder into itself".into());
    }
    let tp = t.parent().ok_or("INVALID: no parent")?;
    let tpm = fs::symlink_metadata(tp).map_err(|_| format!("NOT_FOUND: '{}' does not exist", tp.display()))?;
    if !tpm.is_dir() || tpm.file_type().is_symlink() {
        return Err("INVALID: destination parent is not a regular folder".into());
    }
    ensure_no_links(tp)?;
    fs::rename(&f, &t).map_err(io_err)
}

#[tauri::command]
pub async fn fs_rename(from: String, to: String, user_label: Option<String>) -> Result<(), String> {
    let line = format!("rename {from} -> {to}");
    let res = run_blocking(move || rename_impl(&from, &to)).await;
    audit_result(&user_label, line, &res);
    res
}

// ---------- copy ----------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CopyResult {
    pub op_id: String,
    pub files: u64,
    pub bytes: u64,
    /// Symlinks/junctions inside the source tree that were skipped.
    pub skipped: u64,
}

fn copy_file(src: &Path, dst: &Path, overwrite: bool, op: &mut Op) -> Result<u64, String> {
    match fs::symlink_metadata(dst) {
        Ok(m) => {
            if !m.is_file() || m.file_type().is_symlink() {
                return Err(format!("NOT_FILE: '{}' exists and is not a regular file", dst.display()));
            }
            if !overwrite {
                return Err(format!("EXISTS: '{}' already exists", dst.display()));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_err(e)),
    }
    let parent = dst.parent().ok_or("INVALID: no parent")?;
    let name = dst.file_name().and_then(|n| n.to_str()).ok_or("INVALID: bad file name")?;
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let tmp = parent.join(format!(".{name}.nora-tmp-{}-{nonce}", std::process::id()));
    let result = (|| -> Result<u64, String> {
        let mut input = fs::File::open(src).map_err(io_err)?;
        let mut out = fs::OpenOptions::new().write(true).create_new(true).open(&tmp).map_err(io_err)?;
        let mut buf = vec![0u8; COPY_CHUNK];
        let mut total = 0u64;
        loop {
            let n = input.read(&mut buf).map_err(io_err)?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n]).map_err(io_err)?;
            total += n as u64;
            op.add(n as u64, "copy")?;
        }
        out.sync_all().map_err(io_err)?;
        drop(out);
        fs::rename(&tmp, dst).map_err(io_err)?;
        Ok(total)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn copy_impl(app: Option<AppHandle>, from: &str, to: &str, overwrite: bool, recursive: bool, op_id: Option<String>) -> Result<CopyResult, String> {
    let f = validate_path(from)?;
    let t = validate_path(to)?;
    check_read_allowed(&f)?;
    check_write_allowed(&t)?;
    if is_drive_root(&t) {
        return Err("FORBIDDEN: drive root".into());
    }
    let fm = fs::symlink_metadata(&f).map_err(io_err)?;
    if fm.file_type().is_symlink() {
        return Err("FORBIDDEN: symlinks are not followed".into());
    }
    ensure_no_links(&f)?;
    let tp = t.parent().ok_or("INVALID: no parent")?;
    let tpm = fs::symlink_metadata(tp).map_err(|_| format!("NOT_FOUND: '{}' does not exist", tp.display()))?;
    if !tpm.is_dir() || tpm.file_type().is_symlink() {
        return Err("INVALID: destination parent is not a regular folder".into());
    }
    ensure_no_links(tp)?;
    if fm.is_dir() && (under(&t, &f)) {
        return Err("INVALID: cannot copy a folder into itself".into());
    }
    // Nothing the UI copies may end up inside the vault dir or overwrite the app (covered by write check).
    let mut op = Op::new(app, op_id);
    let mut files = 0u64;
    let mut bytes = 0u64;
    let mut skipped = 0u64;

    if fm.is_file() {
        op.total = fm.len();
        bytes = copy_file(&f, &t, overwrite, &mut op)?;
        files = 1;
        op.emit("copy", true);
        return Ok(CopyResult { op_id: op.id.clone(), files, bytes, skipped });
    }
    if !fm.is_dir() {
        return Err("NOT_FILE: only files and folders can be copied".into());
    }
    if !recursive {
        return Err("INVALID: copying a folder requires recursive: true".into());
    }
    match fs::symlink_metadata(&t) {
        Ok(m) => {
            if !m.is_dir() || m.file_type().is_symlink() {
                return Err(format!("EXISTS: '{}' exists and is not a folder", t.display()));
            }
            if !overwrite {
                return Err(format!("EXISTS: '{}' already exists", t.display()));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_err(e)),
    }
    // Pass 1: size for progress (and sanity).
    for e in WalkDir::new(&f).follow_links(false).into_iter().flatten() {
        let ft = e.file_type();
        if ft.is_file() {
            op.total += e.metadata().map(|m| m.len()).unwrap_or(0);
        }
        op.check()?;
    }
    fs::create_dir_all(&t).map_err(io_err)?;
    for e in WalkDir::new(&f).follow_links(false).sort_by_file_name() {
        let e = e.map_err(|e| format!("INVALID: {e}"))?;
        op.check()?;
        let rel = e.path().strip_prefix(&f).map_err(|_| "INVALID: path error".to_string())?;
        if rel.as_os_str().is_empty() {
            continue;
        }
        let dest: PathBuf = t.join(rel);
        let ft = e.file_type();
        if ft.is_symlink() {
            skipped += 1;
        } else if ft.is_dir() {
            match fs::symlink_metadata(&dest) {
                Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
                Ok(_) => return Err(format!("EXISTS: '{}' exists and is not a folder", dest.display())),
                Err(_) => fs::create_dir(&dest).map_err(io_err)?,
            }
        } else if ft.is_file() {
            bytes += copy_file(e.path(), &dest, overwrite, &mut op)?;
            files += 1;
        }
    }
    op.emit("copy", true);
    Ok(CopyResult { op_id: op.id.clone(), files, bytes, skipped })
}

#[tauri::command]
pub async fn fs_copy(
    app: AppHandle,
    from: String,
    to: String,
    overwrite: Option<bool>,
    recursive: Option<bool>,
    op_id: Option<String>,
    user_label: Option<String>,
) -> Result<CopyResult, String> {
    let line = format!("copy {from} -> {to}");
    let res = run_blocking(move || copy_impl(Some(app), &from, &to, overwrite.unwrap_or(false), recursive.unwrap_or(false), op_id)).await;
    let line = match &res {
        Ok(r) => format!("{line} ({} files, {} bytes)", r.files, r.bytes),
        Err(_) => line,
    };
    audit_result(&user_label, line, &res);
    res
}

// ---------- delete ----------

fn delete_impl(path: &str, recursive: bool, to_bin: bool) -> Result<(), String> {
    let p = validate_path(path)?;
    check_write_allowed(&p)?;
    if is_drive_root(&p) {
        return Err("FORBIDDEN: drive root".into());
    }
    if protects_app_dir(&p) {
        return Err("FORBIDDEN: the application folder cannot be deleted".into());
    }
    let m = fs::symlink_metadata(&p).map_err(io_err)?;
    if m.file_type().is_symlink() {
        return Err("FORBIDDEN: symlinks are not followed".into());
    }
    ensure_no_links(&p)?;
    if m.is_dir() && !recursive {
        let empty = fs::read_dir(&p).map_err(io_err)?.next().is_none();
        if !empty {
            return Err("INVALID: folder is not empty (recursive: true required)".into());
        }
    }
    if to_bin {
        if !has_recycle_bin(&p) {
            return Err("UNSUPPORTED: this drive has no Recycle Bin; pass toRecycleBin:false to delete permanently".into());
        }
        trash::delete(&p).map_err(|e| format!("INVALID: cannot move to Recycle Bin: {e}"))
    } else if m.is_dir() {
        if recursive { fs::remove_dir_all(&p) } else { fs::remove_dir(&p) }.map_err(io_err)
    } else {
        fs::remove_file(&p).map_err(io_err)
    }
}

/// `toRecycleBin` defaults to TRUE. Permanent deletion needs an explicit `toRecycleBin: false`.
#[tauri::command]
pub async fn fs_delete(
    path: String,
    recursive: Option<bool>,
    to_recycle_bin: Option<bool>,
    user_label: Option<String>,
) -> Result<(), String> {
    let bin = to_recycle_bin.unwrap_or(true);
    let line = format!("delete {path} ({})", if bin { "recycle bin" } else { "PERMANENT" });
    let res = run_blocking(move || delete_impl(&path, recursive.unwrap_or(false), bin)).await;
    audit_result(&user_label, line, &res);
    res
}

#[allow(dead_code)]
fn _unused(p: &Path) -> String {
    strip_verbatim(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = Path::new(env!("CARGO_MANIFEST_DIR")).join("target").join("fsops-tests").join(name);
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        PathBuf::from(strip_verbatim(&fs::canonicalize(&d).unwrap()))
    }
    fn s(p: &Path) -> String {
        p.to_string_lossy().to_string()
    }

    #[test]
    fn list_sorted_and_truncated() {
        let d = scratch("list");
        fs::create_dir(d.join("b-dir")).unwrap();
        fs::create_dir(d.join("A-dir")).unwrap();
        for n in ["z.txt", "a.txt", "M.txt"] {
            fs::write(d.join(n), "x").unwrap();
        }
        let r = list_dir_impl(&s(&d), None).unwrap();
        let names: Vec<_> = r.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["A-dir", "b-dir", "a.txt", "M.txt", "z.txt"]);
        assert!(!r.truncated && r.entries[0].is_dir && r.entries[2].size == 1);
        let r = list_dir_impl(&s(&d), Some(2)).unwrap();
        assert!(r.truncated && r.entries.len() == 2);
        assert!(list_dir_impl(&s(&d.join("a.txt")), None).unwrap_err().starts_with("NOT_FILE"));
    }

    #[test]
    fn mkdir_rules() {
        let d = scratch("mkdir");
        assert!(mkdir_impl(&s(&d.join("one")), false).is_ok());
        assert!(mkdir_impl(&s(&d.join("one")), false).unwrap_err().starts_with("EXISTS"));
        assert!(mkdir_impl(&s(&d.join("one")), true).is_ok()); // idempotent
        assert!(mkdir_impl(&s(&d.join("x/y/z")), false).unwrap_err().starts_with("NOT_FOUND"));
        assert!(mkdir_impl(&s(&d.join("x/y/z")), true).is_ok());
        fs::write(d.join("file"), "1").unwrap();
        assert!(mkdir_impl(&s(&d.join("file")), true).unwrap_err().starts_with("EXISTS"));
        assert!(mkdir_impl("D:/Windows/nora-test", false).is_err());
    }

    #[test]
    fn copy_rules() {
        let d = scratch("copy");
        fs::create_dir_all(d.join("src/sub")).unwrap();
        fs::write(d.join("src/a.txt"), "aaa").unwrap();
        fs::write(d.join("src/sub/b.txt"), "bb").unwrap();
        // file copy
        let r = copy_impl(None, &s(&d.join("src/a.txt")), &s(&d.join("a2.txt")), false, false, None).unwrap();
        assert_eq!((r.files, r.bytes), (1, 3));
        assert!(copy_impl(None, &s(&d.join("src/a.txt")), &s(&d.join("a2.txt")), false, false, None).unwrap_err().starts_with("EXISTS"));
        fs::write(d.join("src/a.txt"), "aaaa").unwrap();
        assert!(copy_impl(None, &s(&d.join("src/a.txt")), &s(&d.join("a2.txt")), true, false, None).is_ok());
        assert_eq!(fs::read_to_string(d.join("a2.txt")).unwrap(), "aaaa");
        // folder needs recursive
        assert!(copy_impl(None, &s(&d.join("src")), &s(&d.join("dst")), false, false, None).unwrap_err().starts_with("INVALID"));
        let r = copy_impl(None, &s(&d.join("src")), &s(&d.join("dst")), false, true, None).unwrap();
        assert_eq!((r.files, r.bytes), (2, 6));
        assert_eq!(fs::read_to_string(d.join("dst/sub/b.txt")).unwrap(), "bb");
        assert!(copy_impl(None, &s(&d.join("src")), &s(&d.join("dst")), false, true, None).unwrap_err().starts_with("EXISTS"));
        // into itself
        assert!(copy_impl(None, &s(&d.join("src")), &s(&d.join("src/sub/x")), false, true, None).unwrap_err().starts_with("INVALID"));
        // no temp leftovers
        let left = WalkDir::new(&d).into_iter().flatten().filter(|e| e.file_name().to_string_lossy().contains("nora-tmp")).count();
        assert_eq!(left, 0);
        // cancelled op leaves no temp file
        let mut op = Op::new(None, Some("t-cancel".into()));
        op.total = 10;
        crate::commands::fsutil::cancel_for_test("t-cancel");
        assert!(copy_file(&d.join("src/a.txt"), &d.join("c.txt"), false, &mut op).unwrap_err().contains("cancelled"));
        assert!(!d.join("c.txt").exists());
    }

    #[test]
    fn rename_rules() {
        let d = scratch("rename");
        fs::write(d.join("a.txt"), "a").unwrap();
        fs::write(d.join("b.txt"), "b").unwrap();
        fs::create_dir(d.join("dir")).unwrap();
        assert!(rename_impl(&s(&d.join("a.txt")), &s(&d.join("b.txt"))).unwrap_err().starts_with("EXISTS"));
        assert!(rename_impl(&s(&d.join("a.txt")), &s(&d.join("c.txt"))).is_ok());
        assert!(rename_impl(&s(&d.join("none")), &s(&d.join("n2"))).unwrap_err().starts_with("NOT_FOUND"));
        assert!(rename_impl(&s(&d.join("dir")), &s(&d.join("dir/inner"))).unwrap_err().starts_with("INVALID"));
        assert!(rename_impl(&s(&d.join("c.txt")), &s(&d.join("dir/c.txt"))).is_ok());
        assert!(d.join("dir/c.txt").exists());
    }

    /// Manual check (touches the real Recycle Bin): cargo test --lib recycle -- --ignored
    #[test]
    #[ignore]
    fn recycle_bin_roundtrip() {
        let d = scratch("bin");
        let f = d.join("to-bin.txt");
        fs::write(&f, "bye").unwrap();
        delete_impl(&s(&f), false, true).unwrap();
        assert!(!f.exists());
    }

    #[test]
    fn delete_rules_permanent() {
        let d = scratch("del");
        fs::create_dir_all(d.join("full/sub")).unwrap();
        fs::write(d.join("full/sub/f"), "1").unwrap();
        fs::write(d.join("one"), "1").unwrap();
        assert!(delete_impl(&s(&d.join("full")), false, false).unwrap_err().starts_with("INVALID"));
        assert!(delete_impl(&s(&d.join("full")), true, false).is_ok());
        assert!(!d.join("full").exists());
        assert!(delete_impl(&s(&d.join("one")), false, false).is_ok());
        assert!(delete_impl(&s(&d.join("one")), false, false).unwrap_err().starts_with("NOT_FOUND"));
        assert!(delete_impl("D:/", true, false).unwrap_err().starts_with("FORBIDDEN"));
        assert!(delete_impl("D:/Windows", true, false).unwrap_err().starts_with("FORBIDDEN"));
        // the app's own folder and its parents are protected
        let exe = crate::portable::exe_dir().unwrap();
        assert!(delete_impl(&s(&exe), true, false).unwrap_err().starts_with("FORBIDDEN"));
        assert!(delete_impl(&s(exe.parent().unwrap()), true, false).unwrap_err().starts_with("FORBIDDEN"));
    }
}
