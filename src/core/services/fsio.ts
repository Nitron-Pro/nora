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
