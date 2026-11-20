//! Local text-file IO for in-app editors (Monaco etc.).
//!
//! IPC: `fs_stat`, `fs_read_text`, `fs_write_text`.
//! Security (all enforced here, never in the frontend):
//! - paths must be absolute drive paths (`X:\...` or `X:/...`); UNC, `\\?\`, `\\.\`, `..`, `:` streams,
//!   reserved device names (CON, NUL, COM1...) and Windows-trimmed names (trailing dot/space) are rejected;
//! - symlinks/junctions are never followed: the canonical path must equal the lexical path;
//! - only regular files are read/written;
//! - writes to system locations (Windows, Program Files, ProgramData, ...) and to the app's own
//!   `nora-data` folder are refused; reads of `nora-data/vault` are refused;
//! - writes are atomic (temp file in the SAME folder, fsync, rename) and logged to the audit log.
//! Zero C-Drive: no system temp; the temp file lives next to the target.

use crate::commands::terminal::audit::{self, AuditVerdict, Source};
use base64::Engine;
use serde::Serialize;
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf, Prefix};
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

const DEFAULT_MAX_READ: u64 = 5 * 1024 * 1024;
const HARD_MAX_READ: u64 = 32 * 1024 * 1024;
const MAX_WRITE: usize = 32 * 1024 * 1024;
const MAX_PATH_LEN: usize = 4096;

static WRITE_LOCK: Mutex<()> = Mutex::new(());

// ---------- types ----------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FsStat {
    pub exists: bool,
    pub is_dir: bool,
    pub size: u64,
    /// Modified time, milliseconds since Unix epoch (0 when missing).
    pub mtime: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadTextResult {
    /// Real size of the file on disk.
    pub size: u64,
    pub mtime: u64,
    pub binary: bool,
    pub truncated: bool,
    /// Decoded text, or null for binary / undecodable content (use `base64`).
    pub text: Option<String>,
    /// Detected encoding: "utf8" | "utf16le" | "utf16be" | null (binary / invalid UTF-8).
    pub encoding: Option<String>,
    /// File started with a BOM (preserve it when saving via `bom: true`).
    pub has_bom: bool,
    /// Raw bytes that were read (possibly truncated).
    pub base64: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteResult {
    pub size: u64,
    pub mtime: u64,
}

// ---------- path validation ----------

const RESERVED: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
    "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9", "conin$", "conout$",
];
const PROTECTED_TOP: &[&str] = &[
    "windows", "program files", "program files (x86)", "programdata", "system volume information",
    "$recycle.bin", "recovery", "boot",
];

fn is_reserved(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).trim_end().to_ascii_lowercase();
    RESERVED.contains(&stem.as_str())
}

/// Validate and lexically normalize an absolute drive path. Returns a `PathBuf` with `\` separators.
pub fn validate_path(raw: &str) -> Result<PathBuf, String> {
    if raw.is_empty() || raw.len() > MAX_PATH_LEN {
        return Err("INVALID: empty or too long path".into());
    }
    if raw.contains('\0') || raw.chars().any(|c| c.is_control()) {
        return Err("INVALID: control characters in path".into());
    }
    let unified = raw.replace('/', "\\");
    if unified.starts_with("\\\\") {
        return Err("INVALID: UNC and device paths (\\\\, \\\\?\\, \\\\.\\) are not allowed".into());
    }
    let b = unified.as_bytes();
    if b.len() < 3 || !b[0].is_ascii_alphabetic() || b[1] != b':' || b[2] != b'\\' {
        return Err("INVALID: path must be absolute (X:\\...)".into());
    }
    let mut out = String::new();
    out.push(b[0] as char);
    out.push_str(":\\");
    let mut first = true;
    for comp in unified[3..].split('\\') {
        if comp.is_empty() {
            continue; // tolerate duplicate separators / trailing slash
        }
        if comp == "." || comp == ".." {
            return Err("INVALID: '.' and '..' segments are not allowed".into());
        }
        if comp.contains(':') || comp.contains(['<', '>', '"', '|', '?', '*']) {
            return Err(format!("INVALID: illegal character in '{comp}'"));
        }
        if comp.ends_with('.') || comp.ends_with(' ') {
            return Err(format!("INVALID: name '{comp}' ends with dot or space"));
        }
        if is_reserved(comp) {
            return Err(format!("INVALID: reserved device name '{comp}'"));
        }
        if !first {
            out.push('\\');
        }
        out.push_str(comp);
        first = false;
    }
    Ok(PathBuf::from(out))
}

fn strip_verbatim(p: &Path) -> String {
    let s = p.to_string_lossy().to_string();
    s.strip_prefix("\\\\?\\").unwrap_or(&s).to_string()
}

fn same_path(a: &str, b: &str) -> bool {
    a.trim_end_matches('\\').eq_ignore_ascii_case(b.trim_end_matches('\\'))
}

/// Reject paths whose real location differs from the typed one (symlinks, junctions, subst/network maps).
fn ensure_no_links(path: &Path) -> Result<(), String> {
    let canon = fs::canonicalize(path).map_err(|e| format!("INVALID: cannot resolve path: {e}"))?;
    let want = path.to_string_lossy();
    if !same_path(&strip_verbatim(&canon), &want) {
        return Err("FORBIDDEN: path passes through a symlink/junction or remapped drive".into());
    }
    Ok(())
}

fn top_component(path: &Path) -> Option<String> {
    let mut it = path.components();
    if !matches!(it.next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_))) {
        return None;
    }
    it.next(); // RootDir
    it.next().map(|c| c.as_os_str().to_string_lossy().to_ascii_lowercase())
}

fn under(path: &Path, base: &Path) -> bool {
    let p = path.to_string_lossy().to_ascii_lowercase();
    let b = strip_verbatim(base).to_ascii_lowercase();
    p == b || p.starts_with(&format!("{}\\", b.trim_end_matches('\\')))
}

fn check_write_allowed(path: &Path) -> Result<(), String> {
    if let Some(top) = top_component(path) {
        if PROTECTED_TOP.contains(&top.as_str()) {
            return Err(format!("FORBIDDEN: writing to system location '{top}' is not allowed"));
        }
    }
    if let Ok(data) = crate::portable::data_dir() {
        if under(path, &data) {
            return Err("FORBIDDEN: the application data folder (nora-data) cannot be written from the UI".into());
        }
    }
    Ok(())
}

fn check_read_allowed(path: &Path) -> Result<(), String> {
    if let Ok(data) = crate::portable::data_dir() {
        if under(path, &data.join("vault")) {
            return Err("FORBIDDEN: the vault folder cannot be read from the UI".into());
        }
    }
    Ok(())
}

fn mtime_ms(meta: &fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------- decoding ----------

struct Decoded {
    text: Option<String>,
    encoding: Option<&'static str>,
    has_bom: bool,
    binary: bool,
}

fn decode(bytes: &[u8], truncated: bool) -> Decoded {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return decode_utf8(&bytes[3..], truncated, true);
    }
    if bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF]) {
        let le = bytes[0] == 0xFF;
        let enc = if le { encoding_rs::UTF_16LE } else { encoding_rs::UTF_16BE };
        let (text, _, bad) = enc.decode(&bytes[2..]);
        return Decoded {
            text: if bad { None } else { Some(text.into_owned()) },
            encoding: Some(if le { "utf16le" } else { "utf16be" }),
            has_bom: true,
            binary: false,
        };
    }
    if bytes.iter().take(8192).any(|&b| b == 0) {
        return Decoded { text: None, encoding: None, has_bom: false, binary: true };
    }
    decode_utf8(bytes, truncated, false)
}

fn decode_utf8(bytes: &[u8], truncated: bool, has_bom: bool) -> Decoded {
    match std::str::from_utf8(bytes) {
        Ok(s) => Decoded { text: Some(s.to_string()), encoding: Some("utf8"), has_bom, binary: false },
        Err(e) if truncated && e.error_len().is_none() => {
            // Cut in the middle of a multi-byte char because of maxBytes: drop the partial tail.
            let s = std::str::from_utf8(&bytes[..e.valid_up_to()]).unwrap_or("");
            Decoded { text: Some(s.to_string()), encoding: Some("utf8"), has_bom, binary: false }
        }
        Err(_) => Decoded { text: None, encoding: None, has_bom, binary: false },
    }
}

fn encode_content(content: &str, encoding: &str, bom: bool) -> Result<Vec<u8>, String> {
    match encoding {
        "utf8" => {
            let mut v = Vec::with_capacity(content.len() + 3);
            if bom {
                v.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
            }
            v.extend_from_slice(content.as_bytes());
            Ok(v)
        }
        "utf16le" | "utf16be" => {
            let le = encoding == "utf16le";
            let mut v = Vec::with_capacity(content.len() * 2 + 2);
            if bom {
                v.extend_from_slice(if le { &[0xFF, 0xFE] } else { &[0xFE, 0xFF] });
            }
            for u in content.encode_utf16() {
                v.extend_from_slice(&if le { u.to_le_bytes() } else { u.to_be_bytes() });
            }
            Ok(v)
        }
        "base64" => base64::engine::general_purpose::STANDARD
            .decode(content)
            .map_err(|e| format!("INVALID: bad base64: {e}")),
        other => Err(format!("INVALID: unknown encoding '{other}'")),
    }
}

// ---------- core logic (sync) ----------

fn stat_impl(path: &str) -> Result<FsStat, String> {
    let p = validate_path(path)?;
    match fs::symlink_metadata(&p) {
        Ok(m) => {
            if m.file_type().is_symlink() {
                return Err("FORBIDDEN: symlinks are not followed".into());
            }
            ensure_no_links(&p)?;
            Ok(FsStat { exists: true, is_dir: m.is_dir(), size: if m.is_file() { m.len() } else { 0 }, mtime: mtime_ms(&m) })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(FsStat { exists: false, is_dir: false, size: 0, mtime: 0 })
        }
        Err(e) => Err(format!("INVALID: {e}")),
    }
}

fn read_impl(path: &str, max_bytes: Option<u64>) -> Result<ReadTextResult, String> {
    let p = validate_path(path)?;
    check_read_allowed(&p)?;
    let meta = fs::symlink_metadata(&p).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => format!("NOT_FOUND: {}", p.display()),
        _ => format!("INVALID: {e}"),
    })?;
    if meta.file_type().is_symlink() {
        return Err("FORBIDDEN: symlinks are not followed".into());
    }
    if !meta.is_file() {
        return Err("NOT_FILE: only regular files can be read".into());
    }
    ensure_no_links(&p)?;
    let limit = max_bytes.unwrap_or(DEFAULT_MAX_READ).min(HARD_MAX_READ);
    if max_bytes.map(|m| m > HARD_MAX_READ).unwrap_or(false) {
        return Err(format!("TOO_LARGE: maxBytes exceeds the hard limit of {HARD_MAX_READ} bytes"));
    }
    let size = meta.len();
    let mut buf = Vec::with_capacity(size.min(limit) as usize);
    fs::File::open(&p)
        .map_err(|e| format!("INVALID: {e}"))?
        .take(limit)
        .read_to_end(&mut buf)
        .map_err(|e| format!("INVALID: read failed: {e}"))?;
    let truncated = size > buf.len() as u64;
    let d = decode(&buf, truncated);
    Ok(ReadTextResult {
        size,
        mtime: mtime_ms(&meta),
        binary: d.binary,
        truncated,
        text: d.text,
        encoding: d.encoding.map(String::from),
        has_bom: d.has_bom,
        base64: base64::engine::general_purpose::STANDARD.encode(&buf),
    })
}

#[derive(Debug)]
pub struct WriteArgs {
    pub path: String,
    pub content: String,
    /// "utf8" | "base64" | "utf16le" | "utf16be"
    pub encoding: String,
    /// Write a BOM for utf8/utf16 encodings.
    pub bom: bool,
    pub expected_mtime: Option<u64>,
    pub expected_size: Option<u64>,
    pub user_label: Option<String>,
}
fn default_utf8() -> String { "utf8".into() }

fn write_impl(a: &WriteArgs) -> Result<WriteResult, String> {
    let p = validate_path(&a.path)?;
    check_write_allowed(&p)?;
    let bytes = encode_content(&a.content, &a.encoding, a.bom)?;
    if bytes.len() > MAX_WRITE {
        return Err(format!("TOO_LARGE: content exceeds {MAX_WRITE} bytes"));
    }
    let parent = p.parent().ok_or("INVALID: no parent folder")?;
    let pmeta = fs::symlink_metadata(parent).map_err(|_| format!("NOT_FOUND: folder '{}' does not exist", parent.display()))?;
    if !pmeta.is_dir() || pmeta.file_type().is_symlink() {
        return Err("INVALID: parent is not a regular folder".into());
    }
    ensure_no_links(parent)?;

    let _guard = WRITE_LOCK.lock().map_err(|_| "INVALID: write lock poisoned".to_string())?;
    check_conflict(&p, a)?;

    let name = p.file_name().and_then(|n| n.to_str()).ok_or("INVALID: bad file name")?;
    let nonce = std::time::SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let tmp = parent.join(format!(".{name}.nora-tmp-{}-{nonce}", std::process::id()));
    let res = (|| -> Result<(), String> {
        let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&tmp)
            .map_err(|e| format!("INVALID: cannot create temp file: {e}"))?;
        f.write_all(&bytes).map_err(|e| format!("INVALID: write failed: {e}"))?;
        f.sync_all().map_err(|e| format!("INVALID: fsync failed: {e}"))?;
        drop(f);
        check_conflict(&p, a)?; // re-check right before the swap
        fs::rename(&tmp, &p).map_err(|e| format!("INVALID: cannot replace target: {e}"))
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res?;
    let m = fs::metadata(&p).map_err(|e| format!("INVALID: {e}"))?;
    Ok(WriteResult { size: m.len(), mtime: mtime_ms(&m) })
}

fn check_conflict(p: &Path, a: &WriteArgs) -> Result<(), String> {
    match fs::symlink_metadata(p) {
        Ok(m) => {
            if m.file_type().is_symlink() {
                return Err("FORBIDDEN: symlinks are not followed".into());
            }
            if !m.is_file() {
                return Err("NOT_FILE: target exists and is not a regular file".into());
            }
            ensure_no_links(p)?;
            if let Some(e) = a.expected_mtime {
                if mtime_ms(&m) != e {
                    return Err("CONFLICT: file changed on disk since it was read".into());
                }
            }
            if let Some(e) = a.expected_size {
                if m.len() != e {
                    return Err("CONFLICT: file size changed on disk since it was read".into());
                }
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if a.expected_mtime.is_some() || a.expected_size.is_some() {
                Err("CONFLICT: file was deleted since it was read".into())
            } else {
                Ok(())
            }
        }
        Err(e) => Err(format!("INVALID: {e}")),
    }
}

// ---------- IPC ----------

#[tauri::command]
pub async fn fs_stat(path: String) -> Result<FsStat, String> {
    tokio::task::spawn_blocking(move || stat_impl(&path)).await.map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn fs_read_text(path: String, max_bytes: Option<u64>) -> Result<ReadTextResult, String> {
    tokio::task::spawn_blocking(move || read_impl(&path, max_bytes)).await.map_err(|e| e.to_string())?
}

/// Flat args from JS: `{ path, content, encoding?, bom?, expectedMtime?, expectedSize?, userLabel? }`.
#[tauri::command]
pub async fn fs_write_text(
    path: String,
    content: String,
    encoding: Option<String>,
    bom: Option<bool>,
    expected_mtime: Option<u64>,
    expected_size: Option<u64>,
    user_label: Option<String>,
) -> Result<WriteResult, String> {
    let label = user_label.clone().unwrap_or_else(|| "ui".into());
    let args = WriteArgs {
        path,
        content,
        encoding: encoding.unwrap_or_else(default_utf8),
        bom: bom.unwrap_or(false),
        expected_mtime,
        expected_size,
        user_label,
    };
    let line = format!("write {} ({} chars, {})", args.path, args.content.len(), args.encoding);
    let res = tokio::task::spawn_blocking(move || write_impl(&args)).await.map_err(|e| e.to_string())?;
    match &res {
        Ok(_) => audit::record("fs", &label, Source::Fs, &line, AuditVerdict::Allow, None),
        Err(e) => {
            let code = e.split(':').next().unwrap_or("ERROR").to_string();
            audit::record("fs", &label, Source::Fs, &line, AuditVerdict::Deny, Some(&code));
        }
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = Path::new(env!("CARGO_MANIFEST_DIR")).join("target").join("fsio-tests").join(name);
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        // canonical, \\?\-stripped absolute path
        PathBuf::from(strip_verbatim(&fs::canonicalize(&d).unwrap()))
    }

    fn wargs(path: &Path, content: &str) -> WriteArgs {
        WriteArgs { path: path.to_string_lossy().to_string(), content: content.into(), encoding: "utf8".into(),
            bom: false, expected_mtime: None, expected_size: None, user_label: None }
    }

    #[test]
    fn validates_paths() {
        assert!(validate_path("D:/work/a.txt").is_ok());
        assert_eq!(validate_path("D:/work//a.txt").unwrap(), PathBuf::from("D:\\work\\a.txt"));
        for bad in ["", "relative/a.txt", "\\\\server\\share\\a", "\\\\?\\C:\\a", "//./C:/a", "D:/a/../b", "D:/a/./b",
            "D:/CON", "D:/dir/nul.txt", "D:/a.txt:stream", "D:/a/b.", "D:/a/b ", "D:/a/b?.txt", "D:a.txt"] {
            assert!(validate_path(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn blocks_system_writes() {
        for p in ["D:/Windows/system32/x.txt", "D:/Program Files/app/x", "D:/ProgramData/x", "D:/Program Files (x86)/a"] {
            let v = validate_path(p).unwrap();
            assert!(check_write_allowed(&v).is_err(), "{p}");
        }
        assert!(check_write_allowed(&validate_path("D:/projects/x.txt").unwrap()).is_ok());
    }

    #[test]
    fn decodes_variants() {
        assert_eq!(decode(b"hello", false).text.as_deref(), Some("hello"));
        let d = decode(&[0xEF, 0xBB, 0xBF, b'h', b'i'], false);
        assert!(d.has_bom && d.text.as_deref() == Some("hi"));
        let d = decode(&[0xFF, 0xFE, b'h', 0, b'i', 0], false);
        assert_eq!(d.encoding, Some("utf16le"));
        assert_eq!(d.text.as_deref(), Some("hi"));
        assert!(decode(b"ab\0cd", false).binary);
        assert!(decode(&[0xFF, 0xC0, 0x41], false).text.is_none());
        // truncated mid-char: "é" = C3 A9, cut after C3
        assert_eq!(decode(&[b'a', 0xC3], true).text.as_deref(), Some("a"));
    }

    #[test]
    fn write_read_roundtrip_and_conflict() {
        let dir = scratch("rt");
        let f = dir.join("a.txt");
        let w = write_impl(&wargs(&f, "سلام ✓ line\n")).unwrap();
        let r = read_impl(&f.to_string_lossy(), None).unwrap();
        assert_eq!(r.text.as_deref(), Some("سلام ✓ line\n"));
        assert_eq!(r.size, w.size);
        assert!(!r.truncated && !r.binary);
        // matching expectation succeeds
        let mut a = wargs(&f, "v2");
        a.expected_mtime = Some(w.mtime);
        let w2 = write_impl(&a).unwrap();
        // stale expectation -> CONFLICT
        std::thread::sleep(std::time::Duration::from_millis(20));
        write_impl(&wargs(&f, "v3 changed")).unwrap();
        let mut stale = wargs(&f, "v4");
        stale.expected_mtime = Some(w2.mtime.saturating_sub(5000));
        assert!(write_impl(&stale).unwrap_err().starts_with("CONFLICT:"));
        // no temp leftovers
        let leftovers: Vec<_> = fs::read_dir(&dir).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().contains("nora-tmp")).collect();
        assert!(leftovers.is_empty());
        // deleted file with expectation
        let g = dir.join("gone.txt");
        let mut d = wargs(&g, "x");
        d.expected_size = Some(1);
        assert!(write_impl(&d).unwrap_err().starts_with("CONFLICT:"));
    }

    #[test]
    fn read_limits_and_kinds() {
        let dir = scratch("lim");
        let f = dir.join("big.txt");
        fs::write(&f, "a".repeat(100)).unwrap();
        let r = read_impl(&f.to_string_lossy(), Some(10)).unwrap();
        assert!(r.truncated && r.text.as_deref() == Some("aaaaaaaaaa") && r.size == 100);
        assert!(read_impl(&f.to_string_lossy(), Some(HARD_MAX_READ + 1)).unwrap_err().starts_with("TOO_LARGE"));
        assert!(read_impl(&dir.to_string_lossy(), None).unwrap_err().starts_with("NOT_FILE"));
        assert!(read_impl(&dir.join("none").to_string_lossy(), None).unwrap_err().starts_with("NOT_FOUND"));
        let st = stat_impl(&dir.join("none").to_string_lossy()).unwrap();
        assert!(!st.exists);
        assert!(stat_impl(&dir.to_string_lossy()).unwrap().is_dir);
    }

    #[test]
    fn encodings_on_write() {
        let dir = scratch("enc");
        let f = dir.join("u16.txt");
        let mut a = wargs(&f, "hi");
        a.encoding = "utf16le".into();
        a.bom = true;
        write_impl(&a).unwrap();
        assert_eq!(fs::read(&f).unwrap(), vec![0xFF, 0xFE, b'h', 0, b'i', 0]);
        let r = read_impl(&f.to_string_lossy(), None).unwrap();
        assert_eq!(r.encoding.as_deref(), Some("utf16le"));
        assert!(r.has_bom);
        let mut b = wargs(&f, "AAEC");
        b.encoding = "base64".into();
        write_impl(&b).unwrap();
        assert_eq!(fs::read(&f).unwrap(), vec![0, 1, 2]);
    }
}
