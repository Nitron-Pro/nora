import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  ConnectResult,
  ConnectionStateEvent,
  ReadFileResult,
  RemoteCapabilities,
  RemoteEntry,
  RemoteError,
  RemoteErrorCode,
  RemoteProfile,
} from "@/core/types/remote";

/*
 * Remote file layer (SFTP / FTP / explicit FTPS). Secrets never cross IPC: profiles carry vault ids.
 * Remote paths are POSIX style (`/a/b`). Transfers live in `transfer.ts`.
 * Terminal / exec wrappers are intentionally NOT here.
 * TODO: add terminal / exec wrappers (separate file) once the PTY IPC commands land.
 */

const ERROR_CODES: RemoteErrorCode[] = [
  "HOSTKEY_UNKNOWN",
  "HOSTKEY_CHANGED",
  "CONN_LOST",
  "AUTH_FAILED",
  "CANCELLED",
  "TOO_LARGE",
  "UNSUPPORTED",
  "INVALID",
  "NOT_FOUND",
  "EXISTS",
];

/**
 * Parse an error string returned by a remote/transfer/fsutil command into a typed error.
 * Accepts strings, Error objects or anything else (stringified). The "CANCELLED" match is
 * case-insensitive because fsutil returns lowercase "cancelled".
 */
export function parseRemoteError(err: unknown): RemoteError {
  const raw = typeof err === "string" ? err : err instanceof Error ? err.message : String(err ?? "");
  const trimmed = raw.trim();

  if (/^cancelled\b/i.test(trimmed)) {
    return { code: "CANCELLED", message: trimmed.replace(/^cancelled:?\s*/i, ""), raw };
  }
  for (const code of ERROR_CODES) {
    if (!trimmed.startsWith(code)) continue;
    const rest = trimmed.slice(code.length);
    if (rest !== "" && rest[0] !== ":" && rest[0] !== " ") continue;
    const body = rest.replace(/^:\s*/, "").trim();
    if (code === "HOSTKEY_UNKNOWN") {
      return { code, message: "Unknown host key", fingerprint: body || undefined, raw };
    }
    if (code === "HOSTKEY_CHANGED") {
      // "<found> (expected <old>)"
      const m = /^(\S+)\s*\(expected\s+(\S+?)\)\s*$/.exec(body);
      return {
        code,
        message: "Host key changed (possible man-in-the-middle)",
        fingerprint: m ? m[1] : body || undefined,
        expectedFingerprint: m ? m[2] : undefined,
        raw,
      };
    }
    return { code, message: body, raw };
  }
  return { code: "UNKNOWN", message: trimmed, raw };
}

export function isRemoteError(err: unknown, code: RemoteErrorCode): boolean {
  return parseRemoteError(err).code === code;
}

/** Mirrors Rust `RemoteProfile::effective_port`. */
export function effectivePort(profile: Pick<RemoteProfile, "protocol" | "port">): number {
  return profile.port ?? (profile.protocol === "sftp" ? 22 : 21);
}

export const RemoteService = {
  /** Open a connection. Throws the raw Rust string; use `parseRemoteError` (or `connectWithTrust`). */
  async connect(profile: RemoteProfile): Promise<ConnectResult> {
    return await invoke<ConnectResult>("remote_connect", { profile });
  },

  /**
   * Connect and handle the SSH host-key flow: on `HOSTKEY_UNKNOWN` calls `askTrust`; when it resolves
   * true the fingerprint is stored (`ssh_trust_host`) and the connection is retried once.
   * `HOSTKEY_CHANGED` is NOT trusted automatically: when `allowReplaceChanged` is given and resolves
   * true, the stored key is replaced explicitly.
   */
  async connectWithTrust(
    profile: RemoteProfile,
    askTrust: (err: RemoteError) => Promise<boolean>,
    allowReplaceChanged?: (err: RemoteError) => Promise<boolean>
  ): Promise<ConnectResult> {
    try {
      return await RemoteService.connect(profile);
    } catch (e) {
      const err = parseRemoteError(e);
      const decide =
        err.code === "HOSTKEY_UNKNOWN" ? askTrust : err.code === "HOSTKEY_CHANGED" ? allowReplaceChanged : undefined;
      if (!decide || !err.fingerprint || !(await decide(err))) throw e;
      await RemoteService.trustHost(profile.host.trim(), effectivePort(profile), err.fingerprint);
      return await RemoteService.connect(profile);
    }
  },

  /** Store a host key fingerprint (`SHA256:...`) as trusted. */
  async trustHost(host: string, port: number, fingerprint: string): Promise<void> {
    await invoke("ssh_trust_host", { host, port, fingerprint });
  },

  async disconnect(connId: string): Promise<void> {
    await invoke("remote_disconnect", { connId });
  },

  async capabilities(connId: string): Promise<RemoteCapabilities> {
    return await invoke<RemoteCapabilities>("remote_capabilities", { connId });
  },

  async list(connId: string, path: string): Promise<RemoteEntry[]> {
    return await invoke<RemoteEntry[]>("remote_list", { connId, path });
  },

  async stat(connId: string, path: string): Promise<RemoteEntry> {
    return await invoke<RemoteEntry>("remote_stat", { connId, path });
  },

  async mkdir(connId: string, path: string, recursive = false): Promise<void> {
    await invoke("remote_mkdir", { connId, path, recursive });
  },

  async rename(connId: string, from: string, to: string): Promise<void> {
    await invoke("remote_rename", { connId, from, to });
  },

  async delete(connId: string, path: string, recursive = false): Promise<void> {
    await invoke("remote_delete", { connId, path, recursive });
  },

  /** `mode` is a number, e.g. `0o644`. */
  async chmod(connId: string, path: string, mode: number): Promise<void> {
    await invoke("remote_chmod", { connId, path, mode });
  },

  /** Small files only (2 MiB hard cap, `TOO_LARGE:` otherwise). */
  async readFile(connId: string, path: string): Promise<ReadFileResult> {
    return await invoke<ReadFileResult>("remote_read_file", { connId, path });
  },

  /** `encoding`: "utf8" (content is text, default) or "base64". 2 MiB cap. */
  async writeFile(connId: string, path: string, content: string, encoding: "utf8" | "base64" = "utf8"): Promise<void> {
    await invoke("remote_write_file", { connId, path, content, encoding });
  },

  /** Server-side sha256 (hex). Rejects with `UNSUPPORTED:` when the server cannot do it. */
  async hash(connId: string, path: string, algo = "sha256"): Promise<string> {
    return await invoke<string>("remote_hash", { connId, path, algo });
  },

  /** Subscribe to `remote://connection-state` (reconnecting / connected / lost). */
  onConnectionState(handler: (e: ConnectionStateEvent) => void): Promise<UnlistenFn> {
    return listen<ConnectionStateEvent>("remote://connection-state", (ev) => handler(ev.payload));
  },
};
