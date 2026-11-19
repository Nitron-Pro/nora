import { invoke } from "@tauri-apps/api/core";
import type { SecretInfo, VaultStatus } from "@/core/types/vault";

/**
 * Encrypted secret vault. The frontend can store and delete secrets but can NEVER read them back:
 * other services (remote, ...) receive only vault ids and resolve the secret inside Rust.
 * The vault auto-locks after `auto_lock_secs` of inactivity (no event is emitted: poll `status()`).
 */
export const VaultService = {
  async status(): Promise<VaultStatus> {
    return await invoke<VaultStatus>("vault_status");
  },

  async create(masterPassword: string): Promise<void> {
    await invoke("vault_create", { masterPassword });
  },

  async unlock(masterPassword: string): Promise<void> {
    await invoke("vault_unlock", { masterPassword });
  },

  async lock(): Promise<void> {
    await invoke("vault_lock");
  },

  /** Create or overwrite a secret. Omitted label/kind keep their previous values. */
  async set(id: string, secret: string, label?: string, kind?: string): Promise<void> {
    await invoke("vault_set", { id, secret, label: label ?? null, kind: kind ?? null });
  },

  async delete(id: string): Promise<void> {
    await invoke("vault_delete", { id });
  },

  async list(): Promise<SecretInfo[]> {
    return await invoke<SecretInfo[]>("vault_list");
  },

  async has(id: string): Promise<boolean> {
    return await invoke<boolean>("vault_has", { id });
  },

  /** NOTE: Rust argument names are `old` / `new`. */
  async changeMaster(oldPassword: string, newPassword: string): Promise<void> {
    await invoke("vault_change_master", { old: oldPassword, new: newPassword });
  },

  /** Idle seconds before auto-lock (0 semantics: see vault/mod.rs). */
  async setAutoLock(secs: number): Promise<void> {
    await invoke("vault_set_auto_lock", { secs });
  },

  /** `backupPassword` omitted => encrypted under the current master password. */
  async exportBackup(destPath: string, backupPassword?: string): Promise<void> {
    await invoke("vault_export_backup", { destPath, backupPassword: backupPassword ?? null });
  },

  /** Returns the number of entries read from the backup. */
  async importBackup(srcPath: string, merge: boolean, backupPassword?: string): Promise<number> {
    return await invoke<number>("vault_import_backup", {
      srcPath,
      backupPassword: backupPassword ?? null,
      merge,
    });
  },
};
