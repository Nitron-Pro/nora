/** Mirrors src-tauri/src/commands/snapshot.rs. These structs serialize in camelCase. */

export interface SnapshotInitResult {
  /** Resolved repository path. */
  repo: string;
  created: boolean;
}

/** One file of a commit. Provide exactly one of `localPath`, `contentBase64` or `absent`. */
export interface SnapshotFileSpec {
  /** Repo-relative path using `/` separators, no `..`. */
  path: string;
  localPath?: string;
  contentBase64?: string;
  absent?: boolean;
}

export interface SnapshotCommitOptions {
  metadata?: Record<string, unknown>;
  tag?: string;
  /** "parent" (default): apply on top of the parent tree; "empty": only the given files. */
  base?: "parent" | "empty";
}

export interface SnapshotLogEntry {
  id: string;
  shortId: string;
  message: string;
  metadata: unknown | null;
  /** Unix seconds. */
  time: number;
  tags: string[];
}

export type SnapshotDiffStatus = "added" | "removed" | "modified";

export interface SnapshotDiffFile {
  path: string;
  status: SnapshotDiffStatus;
  binary: boolean;
  oldSize: number;
  newSize: number;
  /** Unified patch; null for binary / too large / over budget. */
  patch: string | null;
  patchSkipped: string | null;
}

export interface SnapshotDiffResult {
  files: SnapshotDiffFile[];
  truncated: boolean;
}

export interface SnapshotRestoreResult {
  status: "restored" | "absent";
  bytes: number;
}

export interface SnapshotFileInfo {
  path: string;
  size: number;
}

export interface SnapshotTagInfo {
  name: string;
  commitId: string;
}

export interface SnapshotReadResult {
  absent: boolean;
  size: number;
  truncated: boolean;
  binary: boolean;
  contentBase64: string;
}
