/**
 * Mirrors src-tauri/src/commands/remote/{mod,transfer,ssh_common}.rs.
 * NOTE: structs in this module serialize in snake_case; IPC command ARGUMENT names are camelCase.
 */

export type RemoteProtocol = "sftp" | "ftp" | "ftps";

/** Connection profile. Contains NO secrets - only vault ids (`secret_ref`, `passphrase_ref`). */
export interface RemoteProfile {
  protocol: RemoteProtocol;
  host: string;
  /** Defaults: sftp 22, ftp/ftps 21. */
  port?: number | null;
  username?: string;
  /** "password" (default) | "key" (SFTP only). */
  auth?: "password" | "key" | null;
  /** Vault id of the password / private key. FTP: empty => anonymous. */
  secret_ref?: string | null;
  /** Vault id of the private key passphrase (SFTP key auth). */
  passphrase_ref?: string | null;
  /** FTPS only: accept invalid / self-signed certificates. */
  trust_invalid_cert?: boolean;
  /** FTP only: legacy code page, e.g. "windows-1256". */
  legacy_encoding?: string | null;
  /** FTP only: passive mode (default true). */
  passive?: boolean | null;
  connect_timeout_secs?: number | null;
}

export interface RemoteCapabilities {
  server_side_copy: boolean;
  exec: boolean;
  hash: boolean;
  chmod: boolean;
  symlinks: boolean;
  utf8_names: boolean;
  resume: boolean;
  mlsd: boolean;
}

export interface ProtocolInfo {
  protocol: string;
  banner: string | null;
  home: string | null;
  tls: boolean;
  encoding: string | null;
  /** SFTP: SHA256 fingerprint of the verified host key. */
  host_key_fingerprint: string | null;
}

export interface ConnectResult {
  conn_id: string;
  capabilities: RemoteCapabilities;
  protocol_info: ProtocolInfo;
}

export type RemoteEntryKind = "file" | "dir" | "symlink" | "other";

export interface RemoteEntry {
  name: string;
  path: string;
  kind: RemoteEntryKind;
  size: number;
  /** Unix seconds. */
  modified: number | null;
  /** POSIX mode bits. */
  permissions: number | null;
  link_target: string | null;
  target_is_dir: boolean | null;
}

export interface ReadFileResult {
  size: number;
  base64: string;
  /** Present when the content is valid UTF-8. */
  text: string | null;
}

// ---- transfers -------------------------------------------------------------

export type TransferDirection = "up" | "down";
export type TransferState = "queued" | "running" | "done" | "failed" | "cancelled";

/** `transfer_enqueue` spec. `local_path` MUST be absolute. */
export interface TransferSpec {
  conn_id: string;
  direction: TransferDirection;
  local_path: string;
  remote_path: string;
  overwrite?: boolean;
  /** Required when the source is a directory. */
  recursive?: boolean;
  group_id?: string | null;
  /** Default: true for downloads, false for uploads. */
  resume?: boolean | null;
}

export interface TransferItem {
  id: string;
  conn_id: string;
  direction: TransferDirection;
  local_path: string;
  remote_path: string;
  state: TransferState;
  bytes: number;
  total: number;
  speed_bps: number;
  error: string | null;
  group_id: string | null;
  overwrite: boolean;
  resume: boolean;
  created_at: number;
}

/** Event `remote://transfer-progress`. */
export interface TransferProgressEvent {
  id: string;
  bytes: number;
  total: number;
  speed_bps: number;
  state: TransferState;
}

/** Event `remote://transfer-done`. */
export interface TransferDoneEvent {
  id: string;
  state: TransferState;
  error: string | null;
}

/** Event `remote://connection-state`. */
export interface ConnectionStateEvent {
  conn_id: string;
  state: "reconnecting" | "connected" | "lost";
  error: string | null;
}

// ---- errors ----------------------------------------------------------------

export type RemoteErrorCode =
  | "HOSTKEY_UNKNOWN"
  | "HOSTKEY_CHANGED"
  | "CONN_LOST"
  | "AUTH_FAILED"
  | "CANCELLED"
  | "TOO_LARGE"
  | "UNSUPPORTED"
  | "INVALID"
  | "NOT_FOUND"
  | "EXISTS"
  | "UNKNOWN";

export interface RemoteError {
  code: RemoteErrorCode;
  /** Human readable text with the machine prefix removed. */
  message: string;
  /** HOSTKEY_UNKNOWN / HOSTKEY_CHANGED: fingerprint offered by the server (`SHA256:...`). */
  fingerprint?: string;
  /** HOSTKEY_CHANGED: fingerprint stored earlier. */
  expectedFingerprint?: string;
  /** Original string returned by Rust. */
  raw: string;
}
