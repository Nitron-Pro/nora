/** Mirrors src-tauri/src/commands/terminal/audit.rs (snake_case on the wire). */

export interface AuditEntry {
  /** UTC `YYYY-MM-DDTHH:MM:SS.mmmZ`. */
  ts: string;
  conn_id: string;
  user_label: string;
  source: "pty" | "exec";
  /** Redacted command line. */
  line: string;
  verdict: "allow" | "deny" | "blocked";
  reason_code: string | null;
}

export interface AuditFilter {
  conn_id?: string;
  source?: "pty" | "exec";
  verdict?: "allow" | "deny" | "blocked";
  /** Case-insensitive substring of the line. */
  text?: string;
  /** Inclusive ISO bounds compared with `ts`. */
  since?: string;
  until?: string;
  /** Default 200, hard cap 5000. */
  limit?: number;
}
