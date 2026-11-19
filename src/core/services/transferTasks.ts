import type { UnlistenFn } from "@tauri-apps/api/event";
import { TransferService } from "@/core/services/transfer";
import { useTaskStore } from "@/core/store/taskStore";
import type { TransferItem, TransferState } from "@/core/types/remote";
import type { TaskStatus } from "@/core/types/task";

/**
 * Bridges remote transfer events into the Task Queue store so uploads / downloads show up on the
 * /tasks pages with live progress (queue tab while active, Today / History once finished).
 * Call `startTransferTaskBridge()` once (idempotent); it returns a stop function.
 */

const PREFIX = "transfer:";
const started = { count: 0, unlisten: [] as UnlistenFn[] };
const finished = new Set<string>(); // guards against late progress events after done
const meta = new Map<string, { title: string; startedAt: number }>();

function baseName(p: string): string {
  const parts = p.split(/[\/]/).filter(Boolean);
  return parts[parts.length - 1] ?? p;
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const u = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(v >= 10 ? 0 : 1)} ${u[i]}`;
}

function titleOf(it: TransferItem): string {
  return `${it.direction === "up" ? "Upload" : "Download"}: ${baseName(it.remote_path || it.local_path)}`;
}

function toStatus(s: TransferState): TaskStatus {
  switch (s) {
    case "running":
      return "running";
    case "queued":
      return "pending";
    case "done":
      return "completed";
    default:
      return "failed";
  }
}

async function ensureMeta(id: string): Promise<void> {
  if (meta.has(id)) return;
  // Reserve first so concurrent events do not trigger several list() calls.
  meta.set(id, { title: `Transfer ${id.slice(0, 8)}`, startedAt: Date.now() });
  try {
    const it = (await TransferService.list()).find((x) => x.id === id);
    if (it) meta.set(id, { title: titleOf(it), startedAt: Date.now() });
  } catch {
    /* keep the generic title */
  }
}

export function startTransferTaskBridge(): () => void {
  started.count += 1;
  if (started.count === 1) {
    const store = () => useTaskStore.getState();
    Promise.all([
      TransferService.onProgress(async (e) => {
        if (finished.has(e.id)) return;
        await ensureMeta(e.id);
        if (finished.has(e.id)) return;
        const m = meta.get(e.id)!;
        const pct = e.total > 0 ? Math.min(100, Math.round((e.bytes / e.total) * 100)) : 0;
        const speed = e.speed_bps > 0 ? ` - ${fmtBytes(e.speed_bps)}/s` : "";
        store().upsertExternalTask({
          id: PREFIX + e.id,
          title: m.title,
          status: toStatus(e.state),
          progress: pct,
          scheduledTime: `${pct}% (${fmtBytes(e.bytes)} / ${e.total > 0 ? fmtBytes(e.total) : "?"})${speed}`,
        });
      }),
      TransferService.onDone(async (e) => {
        finished.add(e.id);
        if (finished.size > 5000) finished.clear();
        await ensureMeta(e.id);
        const m = meta.get(e.id)!;
        const ok = e.state === "done";
        // Make sure the task exists (queued-then-cancelled items never emit progress with a task).
        store().upsertExternalTask({ id: PREFIX + e.id, title: m.title, status: toStatus(e.state) });
        store().finishExternalTask(
          PREFIX + e.id,
          ok ? "success" : "failed",
          ok ? "Transfer completed." : e.state === "cancelled" ? "Cancelled." : e.error ?? "Transfer failed.",
          Date.now() - m.startedAt
        );
        meta.delete(e.id);
      }),
    ])
      .then((u) => {
        if (started.count === 0) u.forEach((f) => f());
        else started.unlisten = u;
      })
      .catch((err) => console.warn("transferTasks: event bridge unavailable (not running in Tauri?)", err));
  }
  return () => {
    started.count = Math.max(0, started.count - 1);
    if (started.count === 0) {
      started.unlisten.forEach((f) => f());
      started.unlisten = [];
    }
  };
}
