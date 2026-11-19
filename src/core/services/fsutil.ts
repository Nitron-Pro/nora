import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  CompareResult,
  FsProgressEvent,
  HashFileResult,
  TreeHashResult,
  TreeInput,
  ZipCreateOptions,
  ZipCreateResult,
  ZipExtractOptions,
  ZipExtractResult,
} from "@/core/types/fsutil";

/**
 * Local filesystem utilities: sha256 hashing, tree manifests / compare, zip create / extract.
 * Long operations emit `fsutil://progress` keyed by `op_id`. Pass your own `opId` (see `newOpId`)
 * to follow progress or cancel BEFORE the call resolves (hash results do not return the op id).
 * Cancelled operations reject with the lowercase string "cancelled" (use `parseRemoteError`).
 */

let opCounter = 0;
export function newOpId(prefix = "ui"): string {
  opCounter += 1;
  return `${prefix}-${Date.now()}-${opCounter}`;
}

export const FsUtilService = {
  async hashFile(path: string, opId?: string): Promise<HashFileResult> {
    return await invoke<HashFileResult>("fs_hash_file", { path, algo: "sha256", opId: opId ?? null });
  },

  async hashTree(
    root: string,
    options: { ignore?: string[]; followSymlinks?: boolean; opId?: string } = {}
  ): Promise<TreeHashResult> {
    return await invoke<TreeHashResult>("fs_hash_tree", {
      root,
      ignore: options.ignore ?? null,
      followSymlinks: options.followSymlinks ?? null,
      opId: options.opId ?? null,
    });
  },

  /** `a` is the baseline: files only in `b` are reported as `added`. */
  async compareTrees(
    a: TreeInput,
    b: TreeInput,
    options: { ignore?: string[]; opId?: string } = {}
  ): Promise<CompareResult> {
    return await invoke<CompareResult>("fs_compare_trees", {
      a,
      b,
      ignore: options.ignore ?? null,
      opId: options.opId ?? null,
    });
  },

  async zipCreate(
    srcRoot: string,
    destZip: string,
    options: ZipCreateOptions & { opId?: string } = {}
  ): Promise<ZipCreateResult> {
    return await invoke<ZipCreateResult>("zip_create", {
      srcRoot,
      destZip,
      include: options.include ?? null,
      exclude: options.exclude ?? null,
      level: options.level ?? null,
      opId: options.opId ?? null,
    });
  },

  async zipExtract(
    zip: string,
    destDir: string,
    options: ZipExtractOptions & { opId?: string } = {}
  ): Promise<ZipExtractResult> {
    return await invoke<ZipExtractResult>("zip_extract", {
      zip,
      destDir,
      overwrite: options.overwrite ?? null,
      maxTotalBytes: options.maxTotalBytes ?? null,
      maxEntries: options.maxEntries ?? null,
      opId: options.opId ?? null,
    });
  },

  /** Returns false when the op was not found (already finished). */
  async cancel(opId: string): Promise<boolean> {
    return await invoke<boolean>("fs_cancel", { opId });
  },

  /** `fsutil://progress`; filter by `op_id` in the handler. */
  onProgress(handler: (e: FsProgressEvent) => void): Promise<UnlistenFn> {
    return listen<FsProgressEvent>("fsutil://progress", (ev) => handler(ev.payload));
  },
};
