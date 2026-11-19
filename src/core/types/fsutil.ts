/** Mirrors src-tauri/src/commands/fsutil.rs. Result structs are camelCase; the progress event is snake_case. */

export interface HashFileResult {
  path: string;
  size: number;
  algo: string;
  hash: string;
}

export interface ManifestEntry {
  relPath: string;
  size: number;
  sha256: string;
}

export interface TreeHashResult {
  root: string;
  entries: ManifestEntry[];
  treeHash: string;
  fileCount: number;
  totalSize: number;
}

/** A tree is a directory path, a manifest array, or `{ entries }`. */
export type TreeInput = string | ManifestEntry[] | { entries: ManifestEntry[] };

export interface ModifiedEntry {
  relPath: string;
  aSize: number;
  bSize: number;
  aSha256: string;
  bSha256: string;
}

export interface CompareResult {
  added: string[];
  removed: string[];
  modified: ModifiedEntry[];
  same: string[];
}

export interface ZipCreateOptions {
  include?: string[];
  exclude?: string[];
  /** 0..9 (default 6). */
  level?: number;
}

export interface ZipCreateResult {
  opId: string;
  destZip: string;
  fileCount: number;
  totalBytes: number;
  zipBytes: number;
}

export interface ZipExtractOptions {
  overwrite?: boolean;
  maxTotalBytes?: number;
  maxEntries?: number;
}

export interface ZipExtractResult {
  opId: string;
  destDir: string;
  files: number;
  dirs: number;
  totalBytes: number;
  skippedSymlinks: number;
}

/** Event `fsutil://progress` (bytes). */
export interface FsProgressEvent {
  op_id: string;
  done: number;
  total: number;
  /** "hash" | "compare" | "zip" | "extract" */
  phase: string;
}
