import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  TransferDoneEvent,
  TransferItem,
  TransferProgressEvent,
  TransferSpec,
} from "@/core/types/remote";

/**
 * Remote transfer queue (backed by Rust). `local_path` must be absolute.
 * For recursive directory transfers `enqueue` returns a GROUP id; the individual items appear in
 * `list()` (event ids are item ids). `cancel` accepts an item id or a group id.
 */
export const TransferService = {
  /** Returns the item id (single file) or the group id (recursive directory). */
  async enqueue(spec: TransferSpec): Promise<string> {
    return await invoke<string>("transfer_enqueue", { spec });
  },

  async cancel(idOrGroupId: string): Promise<void> {
    await invoke("transfer_cancel", { id: idOrGroupId });
  },

  async list(): Promise<TransferItem[]> {
    return await invoke<TransferItem[]>("transfer_list");
  },

  /** Clamped by Rust to 1..=8; returns the effective value. */
  async setConcurrency(n: number): Promise<number> {
    return await invoke<number>("transfer_set_concurrency", { n });
  },

  /** Removes done/failed/cancelled items; returns how many were removed. */
  async clearFinished(): Promise<number> {
    return await invoke<number>("transfer_clear_finished");
  },

  /** `remote://transfer-progress` (~10/s per running item). */
  onProgress(handler: (e: TransferProgressEvent) => void): Promise<UnlistenFn> {
    return listen<TransferProgressEvent>("remote://transfer-progress", (ev) => handler(ev.payload));
  },

  /** `remote://transfer-done` (state is done / failed / cancelled). */
  onDone(handler: (e: TransferDoneEvent) => void): Promise<UnlistenFn> {
    return listen<TransferDoneEvent>("remote://transfer-done", (ev) => handler(ev.payload));
  },
};
