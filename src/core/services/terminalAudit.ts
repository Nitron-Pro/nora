import { invoke } from "@tauri-apps/api/core";
import type { AuditEntry, AuditFilter } from "@/core/types/audit";

/*
 * Terminal command audit log (JSONL under nora-data/logs, secrets redacted by Rust).
 * TODO: terminal / PTY / exec wrappers will be added in a separate file after those IPC commands land.
 */
export const TerminalAuditService = {
  /** Newest first. Default 200 rows, hard cap 5000. */
  async list(filter: AuditFilter = {}): Promise<AuditEntry[]> {
    return await invoke<AuditEntry[]>("terminal_audit_list", { filter });
  },
};
