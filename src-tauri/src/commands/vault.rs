//! Vault IPC layer. The frontend NEVER receives secret values: there is no get-secret command.
//! All commands return `Result<T, String>`; heavy KDF work runs on blocking threads.
//! Register in lib.rs: `commands::vault::{vault_status, vault_create, vault_unlock, vault_lock,
//! vault_set, vault_delete, vault_list, vault_has, vault_change_master, vault_set_auto_lock,
//! vault_export_backup, vault_import_backup}`.

use crate::vault::{self, SecretInfo, VaultStatus};
use std::path::PathBuf;
use zeroize::Zeroizing;

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, String> + Send + 'static) -> Result<T, String> {
    tokio::task::spawn_blocking(f).await.map_err(|e| format!("vault task failed: {e}"))?
}

#[tauri::command]
pub async fn vault_status() -> Result<VaultStatus, String> {
    Ok(vault::global()?.status())
}

#[tauri::command]
pub async fn vault_create(master_password: String) -> Result<(), String> {
    let p = Zeroizing::new(master_password);
    blocking(move || vault::global()?.create(&p)).await
}

#[tauri::command]
pub async fn vault_unlock(master_password: String) -> Result<(), String> {
    let p = Zeroizing::new(master_password);
    blocking(move || vault::global()?.unlock(&p)).await
}

#[tauri::command]
pub async fn vault_lock() -> Result<(), String> {
    vault::global()?.lock();
    Ok(())
}

#[tauri::command]
pub async fn vault_set(id: String, secret: String, label: Option<String>, kind: Option<String>) -> Result<(), String> {
    let s = Zeroizing::new(secret);
    blocking(move || vault::global()?.set(&id, &s, label.as_deref(), kind.as_deref())).await
}

#[tauri::command]
pub async fn vault_delete(id: String) -> Result<(), String> {
    vault::global()?.delete(&id)
}

#[tauri::command]
pub async fn vault_list() -> Result<Vec<SecretInfo>, String> {
    vault::global()?.list()
}

#[tauri::command]
pub async fn vault_has(id: String) -> Result<bool, String> {
    vault::global()?.has(&id)
}

#[tauri::command]
pub async fn vault_change_master(old: String, new: String) -> Result<(), String> {
    let (o, n) = (Zeroizing::new(old), Zeroizing::new(new));
    blocking(move || vault::global()?.change_master(&o, &n)).await
}

#[tauri::command]
pub async fn vault_set_auto_lock(secs: u64) -> Result<(), String> {
    vault::global()?.set_auto_lock(secs)
}

/// `backup_password` None => encrypted under the current master; Some => separate backup password.
#[tauri::command]
pub async fn vault_export_backup(dest_path: String, backup_password: Option<String>) -> Result<(), String> {
    let p = backup_password.map(Zeroizing::new);
    blocking(move || vault::global()?.export_backup(&PathBuf::from(dest_path), p.as_deref().map(|s| s.as_str()))).await
}

/// Returns the number of entries read from the backup.
#[tauri::command]
pub async fn vault_import_backup(src_path: String, backup_password: Option<String>, merge: bool) -> Result<usize, String> {
    let p = backup_password.map(Zeroizing::new);
    blocking(move || vault::global()?.import_backup(&PathBuf::from(src_path), p.as_deref().map(|s| s.as_str()), merge)).await
}
