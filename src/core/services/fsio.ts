import { invoke } from "@tauri-apps/api/core";

/** Local text-file IO for editors. All rules (absolute paths, no symlinks, system folders protected) are enforced in Rust. */
export interface FsStat { exists: boolean; isDir: boolean; size: number; /** ms since epoch */ mtime: number }
export interface ReadTextResult {
  size: number;
  mtime: number;
  binary: boolean;
  truncated: boolean;
  /** null for binary or undecodable content: use `base64` */
  text: string | null;
  encoding: "utf8" | "utf16le" | "utf16be" | null;
  /** File started with a BOM; pass `bom: true` when saving to keep it. */
  hasBom: boolean;
  base64: string;
}
export interface WriteResult { size: number; mtime: number }
export type WriteEncoding = "utf8" | "base64" | "utf16le" | "utf16be";

/** Error strings are prefixed: INVALID: NOT_FOUND: NOT_FILE: FORBIDDEN: TOO_LARGE: CONFLICT: */
export const isConflict = (e: unknown) => String(e).startsWith("CONFLICT:");

export const FsIoService = {
  stat: (path: string) => invoke<FsStat>("fs_stat", { path }),

  /** Default limit 5 MiB, hard limit 32 MiB. */
  readText: (path: string, maxBytes?: number) => invoke<ReadTextResult>("fs_read_text", { path, maxBytes }),

  /**
   * Atomic write (temp file beside the target + rename). Pass the `mtime`/`size` you got from
   * readText/stat/writeText to detect concurrent changes (rejects with "CONFLICT: ...").
   */
  writeText: (opts: {
    path: string;
    content: string;
    encoding?: WriteEncoding;
    bom?: boolean;
    expectedMtime?: number;
    expectedSize?: number;
    userLabel?: string;
  }) => invoke<WriteResult>("fs_write_text", opts),
};

/* ------------------------------------------------------------------------------------------------
 * Local file-manager operations (Rust: commands/fsops.rs). Same security rules as above.
 * Errors: INVALID: NOT_FOUND: NOT_FILE: EXISTS: FORBIDDEN: UNSUPPORTED: and "cancelled".
 * Progress/cancel are shared with fsutil: event `fsutil://progress` {op_id, done, total, phase:"copy"}
 * (FsUtilService.onProgress) and FsUtilService.cancel(opId).
 * ---------------------------------------------------------------------------------------------- */
export interface DriveInfo { letter: string; /** "D:/" */ path: string; kind: "fixed" | "removable" | "network" | "cdrom" | "ramdisk" | "unknown" }
export interface DirEntryInfo { name: string; isDir: boolean; /** symlink/junction: listed, never followed */ isSymlink: boolean; size: number; /** ms */ mtime: number }
export interface ListDirResult { /** folders first, then files, case-insensitive */ entries: DirEntryInfo[]; truncated: boolean }
export interface CopyResult { opId: string; files: number; bytes: number; /** symlinks/junctions skipped inside the source tree */ skipped: number }

export const FsOpsService = {
  listDrives: () => invoke<DriveInfo[]>("fs_list_drives"),
  /** Default limit 20 000 entries, hard limit 100 000 (`truncated` tells you). */
  listDir: (path: string, maxEntries?: number) => invoke<ListDirResult>("fs_list_dir", { path, maxEntries }),
  mkdir: (path: string, recursive = false, userLabel?: string) => invoke<void>("fs_mkdir", { path, recursive, userLabel }),
  /** Same drive only; rejects with EXISTS: if the target exists. */
  rename: (from: string, to: string, userLabel?: string) => invoke<void>("fs_rename", { from, to, userLabel }),
  /** `to` is the full target path (not its parent). Folders need recursive. Pass opId to follow progress / cancel. */
  copy: (opts: { from: string; to: string; overwrite?: boolean; recursive?: boolean; opId?: string; userLabel?: string }) =>
    invoke<CopyResult>("fs_copy", opts),
  /** Moves to the Recycle Bin by default; permanent deletion only with toRecycleBin:false. */
  delete: (opts: { path: string; recursive?: boolean; toRecycleBin?: boolean; userLabel?: string }) =>
    invoke<void>("fs_delete", opts),
};
