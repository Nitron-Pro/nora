//! Portable-First storage (Zero C-Drive Pollution).
//!
//! Every file the app writes (settings, db, logs, vault, known_hosts, git repos, WebView2 data)
//! must live next to the executable under `nora-data/`. Never use `%APPDATA%`, `%LOCALAPPDATA%`,
//! `%TEMP%`, `app_data_dir`, `app_local_data_dir`, `std::env::temp_dir` or the `dirs` crate.
//! `scripts/check-portable.mjs` enforces this at build time.

use std::fs;
use std::path::PathBuf;

/// Directory containing the running executable.
pub fn exe_dir() -> Result<PathBuf, String> {
    std::env::current_exe()
        .map_err(|e| format!("cannot locate executable: {e}"))?
        .parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| "executable has no parent directory".to_string())
}

/// Root data directory: `<exe_dir>/nora-data` (created on demand).
/// There is intentionally NO fallback to the Windows drive: if the exe folder is not writable
/// the call fails with a clear error and the app must be moved to a writable location.
pub fn data_dir() -> Result<PathBuf, String> {
    let dir = exe_dir()?.join("nora-data");
    fs::create_dir_all(&dir).map_err(|e| {
        format!(
            "cannot create data folder '{}': {e}. Move the app to a writable folder (not Program Files).",
            dir.display()
        )
    })?;
    Ok(dir)
}

/// A named sub-folder of the data directory (e.g. `data_subdir("vault")`).
/// `name` must be a simple relative name without `..` or absolute components.
pub fn data_subdir(name: &str) -> Result<PathBuf, String> {
    if name.is_empty()
        || name.contains("..")
        || name.contains(':')
        || name.starts_with('/')
        || name.starts_with('\\')
    {
        return Err(format!("invalid data sub-folder name: '{name}'"));
    }
    let dir = data_dir()?.join(name);
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create '{}': {e}", dir.display()))?;
    Ok(dir)
}

/// Redirect the WebView2 user-data folder (localStorage, cache, cookies) next to the exe.
/// Must run before the first webview is created (start of `run()`).
pub fn init_webview_data_dir() {
    if std::env::var_os("WEBVIEW2_USER_DATA_FOLDER").is_some() {
        return;
    }
    match data_subdir("webview") {
        Ok(dir) => std::env::set_var("WEBVIEW2_USER_DATA_FOLDER", dir),
        Err(e) => eprintln!("[portable] WebView2 data redirect failed: {e}"),
    }
}
