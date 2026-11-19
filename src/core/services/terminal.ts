import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

/** Connection profile for SSH terminal/exec (secrets are vault ids only). */
export interface SshProfile {
  host: string;
  port?: number;
  username: string;
  auth?: "password" | "key";
  secret_ref?: string;
  passphrase_ref?: string;
  connect_timeout_secs?: number;
  keepalive_secs?: number;
}

/**
 * Guard policy. Default (no policy) = deny everything. Enforced in Rust only.
 * Arg patterns: literal | "*" (one arg) | "**" (rest, last only) | "<int>" | "<word>" | "<path-under:/prefix>".
 */
export type GuardRule =
  | { type: "exact"; line: string }
  | {
      type: "command";
      command: string;
      args?: string[];
      allow_chaining?: { pipe?: boolean; and?: boolean; or?: boolean; semicolon?: boolean; redirect?: boolean };
    };
export interface GuardPolicy {
  rules: GuardRule[];
  deny_substrings?: string[];
  max_line_len?: number;
  allow_non_ascii_args?: boolean;
}

export type TerminalState = "starting" | "ready" | "running" | "error" | "closed";
export interface TerminalInfo {
  term_id: string; host: string; port: number; username: string; user_label?: string;
  state: TerminalState; cols: number; rows: number; created_unix: number;
}
export interface AuditEntry {
  ts: string; conn_id: string; user_label?: string; source: "pty" | "exec";
  line: string; verdict: "allow" | "deny" | "blocked"; reason_code?: string;
}
export interface AuditFilter {
  conn_id?: string; source?: string; verdict?: string; text?: string; since?: string; until?: string; limit?: number;
}

const b64ToBytes = (b64: string): Uint8Array => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

export const TerminalService = {
  async open(req: { profile: SshProfile; policy?: GuardPolicy; cols: number; rows: number; user_label?: string; idle_timeout_secs?: number }) {
    return invoke<{ term_id: string }>("terminal_open", { req });
  },
  write: (termId: string, data: string) => invoke<void>("terminal_write", { termId, data }),
  resize: (termId: string, cols: number, rows: number) => invoke<void>("terminal_resize", { termId, cols, rows }),
  close: (termId: string) => invoke<void>("terminal_close", { termId }),
  setPolicy: (termId: string, policy?: GuardPolicy) => invoke<void>("terminal_set_policy", { termId, policy }),
  list: () => invoke<TerminalInfo[]>("terminal_list"),

  /** Run one guarded command. Rejects with "DENIED:<reason_code>:<message>" when not allowed. */
  exec: (req: { profile: SshProfile; command: string; policy?: GuardPolicy; timeout_secs?: number; max_output_bytes?: number; user_label?: string; session_key?: string }) =>
    invoke<{ exec_id: string }>("exec_run", { req }),
  execCancel: (execId: string) => invoke<void>("exec_cancel", { execId }),
  auditList: (filter?: AuditFilter) => invoke<AuditEntry[]>("terminal_audit_list", { filter }),

  /**
   * Events can fire before `open()` resolves; subscribe once for ALL terminals and filter by term_id
   * (buffer until you know your id).
   */
  onData: (cb: (e: { term_id: string; bytes: Uint8Array }) => void): Promise<UnlistenFn> =>
    listen<{ term_id: string; data_b64: string }>("terminal://data", (ev) =>
      cb({ term_id: ev.payload.term_id, bytes: b64ToBytes(ev.payload.data_b64) })),
  onExit: (cb: (e: { term_id: string; code?: number }) => void) => listen<{ term_id: string; code?: number }>("terminal://exit", (ev) => cb(ev.payload)),
  onDenied: (cb: (e: { term_id: string; line: string; reason_code: string; message: string }) => void) =>
    listen<{ term_id: string; line: string; reason_code: string; message: string }>("terminal://denied", (ev) => cb(ev.payload)),
  onState: (cb: (e: { term_id: string; state: TerminalState }) => void) =>
    listen<{ term_id: string; state: TerminalState }>("terminal://state", (ev) => cb(ev.payload)),
  onExecData: (cb: (e: { exec_id: string; stream: "stdout" | "stderr"; bytes: Uint8Array }) => void) =>
    listen<{ exec_id: string; stream: "stdout" | "stderr"; data_b64: string }>("terminal://exec-data", (ev) =>
      cb({ exec_id: ev.payload.exec_id, stream: ev.payload.stream, bytes: b64ToBytes(ev.payload.data_b64) })),
  onExecDone: (cb: (e: { exec_id: string; exit_status?: number; timed_out: boolean; truncated: boolean; error?: string }) => void) =>
    listen<{ exec_id: string; exit_status?: number; timed_out: boolean; truncated: boolean; error?: string }>("terminal://exec-done", (ev) => cb(ev.payload)),
};
