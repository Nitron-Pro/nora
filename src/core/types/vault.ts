/** Mirrors src-tauri/src/vault/mod.rs (struct fields are snake_case on the wire). */
export interface VaultStatus {
  exists: boolean;
  unlocked: boolean;
  auto_lock_secs: number;
}

export interface SecretInfo {
  id: string;
  label: string;
  /** "password" by default; free text up to 32 chars (e.g. "key", "token"). */
  kind: string;
  /** Unix seconds. */
  updated_at: number;
}
