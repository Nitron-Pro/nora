import { invoke } from "@tauri-apps/api/core";
import type {
  SnapshotCommitOptions,
  SnapshotDiffResult,
  SnapshotFileInfo,
  SnapshotFileSpec,
  SnapshotInitResult,
  SnapshotLogEntry,
  SnapshotReadResult,
  SnapshotRestoreResult,
  SnapshotTagInfo,
} from "@/core/types/snapshot";

/**
 * Local snapshots (bare libgit2 repo, no system git). `repo` is either an absolute path or a plain
 * repo id (`[A-Za-z0-9_.-]+`, stored under nora-data/snapshots/<id>).
 * Commit-ish arguments accept commit ids, tags, `HEAD`, `HEAD~1`...; `diff` also accepts
 * `WORKDIR:<dir>` as either side.
 */
export const SnapshotService = {
  /** Provide `repoPath` or `repoId`. Opens the repo when it already exists (`created: false`). */
  async init(opts: { repoPath?: string; repoId?: string }): Promise<SnapshotInitResult> {
    return await invoke<SnapshotInitResult>("snapshot_init", {
      repoPath: opts.repoPath ?? null,
      repoId: opts.repoId ?? null,
    });
  },

  /** Returns the new commit id. */
  async commit(
    repo: string,
    files: SnapshotFileSpec[],
    message: string,
    options: SnapshotCommitOptions = {}
  ): Promise<string> {
    return await invoke<string>("snapshot_commit", {
      repo,
      files,
      message,
      metadata: options.metadata ?? null,
      tag: options.tag ?? null,
      base: options.base ?? null,
    });
  },

  /** Newest first. With `path`, only commits that touched that file. Default limit 50, max 1000. */
  async log(repo: string, limit?: number, path?: string): Promise<SnapshotLogEntry[]> {
    return await invoke<SnapshotLogEntry[]>("snapshot_log", { repo, limit: limit ?? null, path: path ?? null });
  },

  async diff(repo: string, from: string, to: string): Promise<SnapshotDiffResult> {
    return await invoke<SnapshotDiffResult>("snapshot_diff", { repo, from, to });
  },

  /** Writes `path` as of `commit` to `destPath`; status "absent" means nothing was written. */
  async restoreFile(repo: string, commit: string, path: string, destPath: string): Promise<SnapshotRestoreResult> {
    return await invoke<SnapshotRestoreResult>("snapshot_restore_file", { repo, commit, path, destPath });
  },

  async listFiles(repo: string, commit: string): Promise<SnapshotFileInfo[]> {
    return await invoke<SnapshotFileInfo[]>("snapshot_list_files", { repo, commit });
  },

  /** `force` defaults to true in Rust. */
  async tag(repo: string, name: string, commit: string, force?: boolean): Promise<void> {
    await invoke("snapshot_tag", { repo, name, commit, force: force ?? null });
  },

  async listTags(repo: string): Promise<SnapshotTagInfo[]> {
    return await invoke<SnapshotTagInfo[]>("snapshot_list_tags", { repo });
  },

  /** Base64 content, capped by `maxBytes` (default 1 MiB, hard cap 32 MiB). */
  async readFile(repo: string, commit: string, path: string, maxBytes?: number): Promise<SnapshotReadResult> {
    return await invoke<SnapshotReadResult>("snapshot_read_file", { repo, commit, path, maxBytes: maxBytes ?? null });
  },

  /** Convenience: decode `readFile` content as UTF-8 text (null when absent/binary). */
  async readText(repo: string, commit: string, path: string, maxBytes?: number): Promise<string | null> {
    const r = await SnapshotService.readFile(repo, commit, path, maxBytes);
    if (r.absent || r.binary) return null;
    const bin = atob(r.contentBase64);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  },
};
