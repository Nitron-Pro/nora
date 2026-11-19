import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Input } from "@/components/ui/Input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { DiffViewer, type DiffMode } from "@/core/components/DiffViewer";
import { FileDualPane, type TransferInfo } from "@/core/components/FileDualPane";
import type { FileEntry, FileSort } from "@/core/components/VirtualFileList";
import { useNotificationStore } from "@/core/store/notificationStore";
import { VaultService } from "@/core/services/vault";
import { RemoteService, parseRemoteError, effectivePort } from "@/core/services/remote";
import { TransferService } from "@/core/services/transfer";
import { TerminalService, type AuditEntry, type SshProfile, type GuardPolicy } from "@/core/services/terminal";
import { Terminal, type TerminalHandle } from "@/core/components/Terminal";
import { SnapshotService } from "@/core/services/snapshot";
import { FsUtilService, newOpId } from "@/core/services/fsutil";
import { startTransferTaskBridge } from "@/core/services/transferTasks";
import type { SecretInfo, VaultStatus } from "@/core/types/vault";
import type {
  ConnectResult,
  RemoteEntry,
  RemoteError,
  RemoteProfile,
  RemoteProtocol,
  TransferItem,
} from "@/core/types/remote";
import type { SnapshotDiffResult, SnapshotLogEntry } from "@/core/types/snapshot";
import type { FsProgressEvent } from "@/core/types/fsutil";

/**
 * DEV-ONLY manual test page for the core IPC capabilities (route `/lab`).
 * Every tab calls the real service wrappers; results are dumped as JSON under each form.
 */

type TabId = "vault" | "remote" | "transfers" | "snapshots" | "hashzip" | "diff" | "terminal";
const TABS: { id: TabId; label: string }[] = [
  { id: "vault", label: "Vault" },
  { id: "remote", label: "Remote" },
  { id: "transfers", label: "Transfers" },
  { id: "snapshots", label: "Snapshots" },
  { id: "hashzip", label: "Hash / Zip" },
  { id: "diff", label: "Diff" },
  { id: "terminal", label: "Terminal" },
];

// ---------------------------------------------------------------- small helpers

function errText(e: unknown): string {
  const p = parseRemoteError(e);
  return p.code === "UNKNOWN" ? p.message : `${p.code}: ${p.message}${p.fingerprint ? ` [${p.fingerprint}]` : ""}`;
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1 text-[11px] text-muted-foreground min-w-[140px] flex-1">
      <span>{label}</span>
      {children}
    </label>
  );
}

function Out({ value }: { value: unknown }) {
  if (value === undefined) return null;
  const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  return (
    <pre
      dir="ltr"
      className="mt-3 max-h-72 overflow-auto rounded-lg border border-border bg-muted/30 p-3 text-[11px] font-mono whitespace-pre-wrap break-all"
    >
      {text}
    </pre>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card className="mb-4">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">{title}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">{children}</CardContent>
    </Card>
  );
}

const Row = ({ children }: { children: ReactNode }) => <div className="flex flex-wrap items-end gap-2">{children}</div>;

const textareaCls =
  "w-full rounded-lg border border-input bg-transparent p-2 text-xs font-mono shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring";

/** Runs an async action, stores its result/error, and toasts failures. */
function useAction() {
  const { toast } = useNotificationStore();
  const [out, setOut] = useState<unknown>(undefined);
  const [busy, setBusy] = useState(false);
  const run = useCallback(
    async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
      setBusy(true);
      try {
        const r = await fn();
        setOut(r === undefined ? "OK" : r);
        return r;
      } catch (e) {
        setOut(`ERROR: ${errText(e)}`);
        toast({ type: "error", title: "Core Lab", message: errText(e) });
        return undefined;
      } finally {
        setBusy(false);
      }
    },
    [toast]
  );
  return { out, setOut, busy, run };
}

const joinPosix = (base: string, name: string) => (base.endsWith("/") ? base : base + "/") + name;
const joinLocal = (base: string, name: string) => {
  const sep = base.includes("\\") ? "\\" : "/";
  return base.endsWith(sep) ? base + name : base + sep + name;
};
const parentPosix = (p: string) => {
  const t = p.replace(/\/+$/, "");
  const i = t.lastIndexOf("/");
  return i <= 0 ? "/" : t.slice(0, i);
};

// ---------------------------------------------------------------- Vault

function VaultTab() {
  const { out, run, busy } = useAction();
  const [status, setStatus] = useState<VaultStatus | null>(null);
  const [secrets, setSecrets] = useState<SecretInfo[]>([]);
  const [master, setMaster] = useState("");
  const [id, setId] = useState("demo-secret");
  const [secret, setSecret] = useState("");
  const [label, setLabel] = useState("");

  const refresh = useCallback(async () => {
    try {
      const s = await VaultService.status();
      setStatus(s);
      setSecrets(s.unlocked ? await VaultService.list() : []);
    } catch (e) {
      setStatus(null);
      setSecrets([]);
      console.warn(errText(e));
    }
  }, []);
  useEffect(() => {
    void refresh();
    const t = setInterval(refresh, 5000); // auto-lock emits no event
    return () => clearInterval(t);
  }, [refresh]);

  const act = async (fn: () => Promise<unknown>) => {
    await run(fn);
    await refresh();
  };

  return (
    <>
      <Section title="Status">
        <div className="flex items-center gap-2 text-xs">
          <Badge variant={status?.exists ? "success" : "secondary"}>exists: {String(status?.exists ?? "?")}</Badge>
          <Badge variant={status?.unlocked ? "success" : "warning"}>unlocked: {String(status?.unlocked ?? "?")}</Badge>
          <Badge variant="outline">auto-lock: {status?.auto_lock_secs ?? "?"}s</Badge>
          <Button size="sm" variant="outline" onClick={refresh}>Refresh</Button>
        </div>
        <Row>
          <Field label="Master password">
            <Input type="password" value={master} onChange={(e) => setMaster(e.target.value)} />
          </Field>
          <Button disabled={busy || !master} onClick={() => act(() => VaultService.create(master))}>Create</Button>
          <Button disabled={busy || !master} variant="secondary" onClick={() => act(() => VaultService.unlock(master))}>Unlock</Button>
          <Button disabled={busy} variant="outline" onClick={() => act(() => VaultService.lock())}>Lock</Button>
        </Row>
      </Section>

      <Section title="Secrets (values can never be read back)">
        <Row>
          <Field label="Id"><Input value={id} onChange={(e) => setId(e.target.value)} /></Field>
          <Field label="Label"><Input value={label} onChange={(e) => setLabel(e.target.value)} /></Field>
          <Field label="Secret">
            <Input type="password" value={secret} onChange={(e) => setSecret(e.target.value)} />
          </Field>
          <Button
            disabled={busy || !id || !secret}
            onClick={() => act(() => VaultService.set(id, secret, label || undefined, "password"))}
          >
            Set
          </Button>
          <Button disabled={busy || !id} variant="destructive" onClick={() => act(() => VaultService.delete(id))}>
            Delete
          </Button>
        </Row>
        <table className="w-full text-xs">
          <thead className="text-muted-foreground text-left">
            <tr><th>Id</th><th>Label</th><th>Kind</th><th>Updated</th></tr>
          </thead>
          <tbody>
            {secrets.map((s) => (
              <tr key={s.id} className="border-t border-border/60 cursor-pointer hover:bg-muted/30" onClick={() => setId(s.id)}>
                <td className="py-1 font-mono">{s.id}</td>
                <td>{s.label}</td>
                <td>{s.kind}</td>
                <td>{new Date(s.updated_at * 1000).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <Out value={out} />
      </Section>
    </>
  );
}

// ---------------------------------------------------------------- Remote

interface RemoteState {
  connId: string;
  setConnId: (id: string) => void;
}

function toFileEntry(e: RemoteEntry): FileEntry {
  const isDir = e.kind === "dir" || (e.kind === "symlink" && e.target_is_dir === true);
  return {
    name: e.name,
    path: e.path,
    isDir,
    size: isDir ? undefined : e.size,
    modified: e.modified != null ? e.modified * 1000 : undefined,
    mode: e.permissions != null ? (e.permissions & 0o7777).toString(8) : undefined,
  };
}

function RemoteTab({ connId, setConnId }: RemoteState) {
  const { out, setOut, run, busy } = useAction();
  const { toast } = useNotificationStore();
  const [secrets, setSecrets] = useState<SecretInfo[]>([]);
  const [protocol, setProtocol] = useState<RemoteProtocol>("sftp");
  const [host, setHost] = useState("");
  const [port, setPort] = useState("");
  const [username, setUsername] = useState("");
  const [auth, setAuth] = useState<"password" | "key">("password");
  const [secretRef, setSecretRef] = useState("");
  const [trustInvalid, setTrustInvalid] = useState(false);
  const [conn, setConn] = useState<ConnectResult | null>(null);
  const [trustPrompt, setTrustPrompt] = useState<{ err: RemoteError; resolve: (ok: boolean) => void } | null>(null);

  // remote pane
  const [rPath, setRPath] = useState("/");
  const [rEntries, setREntries] = useState<FileEntry[]>([]);
  const [rSel, setRSel] = useState<Set<string>>(new Set());
  const [rLoading, setRLoading] = useState(false);
  const [rSort, setRSort] = useState<FileSort>({ key: "name", dir: "asc" });
  // local pane (no local-listing IPC exists yet: the list is a manual text area)
  const [lPath, setLPath] = useState("");
  const [lText, setLText] = useState("file1.txt\nfile2.txt\nsubfolder/");
  const [lSel, setLSel] = useState<Set<string>>(new Set());
  const [lSort, setLSort] = useState<FileSort>({ key: "name", dir: "asc" });
  const [active, setActive] = useState<"left" | "right">("right");
  // file ops
  const [newName, setNewName] = useState("");
  const [writeText, setWriteText] = useState("hello from Nora");

  useEffect(() => {
    VaultService.list().then(setSecrets).catch(() => setSecrets([]));
  }, []);

  useEffect(() => {
    let un: (() => void) | undefined;
    RemoteService.onConnectionState((e) => {
      toast({ type: e.state === "lost" ? "error" : "info", title: `Connection ${e.state}`, message: e.error ?? e.conn_id });
    })
      .then((f) => (un = f))
      .catch(() => undefined);
    return () => un?.();
  }, [toast]);

  const loadRemote = useCallback(
    async (path: string, id = connId) => {
      if (!id) return;
      setRLoading(true);
      try {
        const list = await RemoteService.list(id, path);
        setREntries(list.map(toFileEntry));
        setRPath(path);
        setRSel(new Set());
      } catch (e) {
        setOut(`ERROR: ${errText(e)}`);
        toast({ type: "error", title: "List failed", message: errText(e) });
      } finally {
        setRLoading(false);
      }
    },
    [connId, setOut, toast]
  );

  const profile = (): RemoteProfile => ({
    protocol,
    host: host.trim(),
    port: port ? Number(port) : null,
    username,
    auth: protocol === "sftp" ? auth : null,
    secret_ref: secretRef || null,
    trust_invalid_cert: trustInvalid,
  });

  const connect = async () => {
    const r = await run(() =>
      RemoteService.connectWithTrust(
        profile(),
        (err) => new Promise<boolean>((resolve) => setTrustPrompt({ err, resolve })),
        (err) => new Promise<boolean>((resolve) => setTrustPrompt({ err, resolve }))
      )
    );
    setTrustPrompt(null);
    if (r) {
      setConn(r);
      setConnId(r.conn_id);
      await loadRemote(r.protocol_info.home || "/", r.conn_id);
    }
  };

  const answerTrust = (ok: boolean) => {
    trustPrompt?.resolve(ok);
    setTrustPrompt(null);
  };

  const selectedPaths = [...rSel];
  const lEntries = useMemo<FileEntry[]>(
    () =>
      lText
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean)
        .map((l) => {
          const isDir = l.endsWith("/");
          const name = l.replace(/\/+$/, "");
          return { name, path: lPath ? joinLocal(lPath, name) : name, isDir };
        }),
    [lText, lPath]
  );

  const onTransfer = async (info: TransferInfo) => {
    if (!connId) return toast({ type: "warning", title: "Not connected", message: "Connect first." });
    const items = info.from === "left"
      ? info.entries.map((e) => ({ direction: "up" as const, local: e.path, remote: joinPosix(info.targetPath, e.name), dir: e.isDir }))
      : info.entries.map((e) => ({ direction: "down" as const, local: joinLocal(lPath || info.targetPath, e.name), remote: e.path, dir: e.isDir }));
    const ids = await run(async () => {
      const res: string[] = [];
      for (const it of items) {
        res.push(
          await TransferService.enqueue({
            conn_id: connId,
            direction: it.direction,
            local_path: it.local, // must be an absolute local path
            remote_path: it.remote,
            recursive: it.dir,
            overwrite: true,
          })
        );
      }
      return { enqueued: res };
    });
    if (ids) toast({ type: "info", title: "Transfers queued", message: "See the Transfers tab / Tasks queue." });
  };

  return (
    <>
      <Section title="Connect">
        <Row>
          <Field label="Protocol">
            <select className="h-8 rounded-lg border border-input bg-background px-2 text-xs" value={protocol} onChange={(e) => setProtocol(e.target.value as RemoteProtocol)}>
              <option value="sftp">sftp</option>
              <option value="ftp">ftp</option>
              <option value="ftps">ftps</option>
            </select>
          </Field>
          <Field label="Host"><Input value={host} onChange={(e) => setHost(e.target.value)} placeholder="host.example.com" /></Field>
          <Field label={`Port (default ${effectivePort({ protocol, port: null })})`}>
            <Input value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, ""))} />
          </Field>
          <Field label="Username"><Input value={username} onChange={(e) => setUsername(e.target.value)} /></Field>
        </Row>
        <Row>
          {protocol === "sftp" && (
            <Field label="Auth">
              <select className="h-8 rounded-lg border border-input bg-background px-2 text-xs" value={auth} onChange={(e) => setAuth(e.target.value as "password" | "key")}>
                <option value="password">password</option>
                <option value="key">key</option>
              </select>
            </Field>
          )}
          <Field label="Vault secret id (empty = anonymous FTP)">
            <Input list="lab-secret-ids" value={secretRef} onChange={(e) => setSecretRef(e.target.value)} />
            <datalist id="lab-secret-ids">{secrets.map((s) => <option key={s.id} value={s.id} />)}</datalist>
          </Field>
          {protocol === "ftps" && (
            <label className="flex items-center gap-1 text-[11px]">
              <input type="checkbox" checked={trustInvalid} onChange={(e) => setTrustInvalid(e.target.checked)} /> trust invalid cert
            </label>
          )}
          <Button disabled={busy || !host} onClick={connect}>Connect</Button>
          <Button disabled={!connId} variant="outline" onClick={async () => { await run(() => RemoteService.disconnect(connId)); setConnId(""); setConn(null); setREntries([]); }}>
            Disconnect
          </Button>
          <Button size="sm" variant="ghost" onClick={() => VaultService.list().then(setSecrets).catch(() => undefined)}>Reload secrets</Button>
        </Row>
        {trustPrompt && (
          <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs space-y-2">
            <p className="font-medium">
              {trustPrompt.err.code === "HOSTKEY_CHANGED"
                ? "WARNING: the host key CHANGED (possible man-in-the-middle)."
                : "Unknown host key (first contact)."}
            </p>
            <p dir="ltr" className="font-mono break-all">
              {trustPrompt.err.fingerprint}
              {trustPrompt.err.expectedFingerprint ? ` (stored: ${trustPrompt.err.expectedFingerprint})` : ""}
            </p>
            <div className="flex gap-2">
              <Button size="sm" onClick={() => answerTrust(true)}>Trust and continue</Button>
              <Button size="sm" variant="outline" onClick={() => answerTrust(false)}>Reject</Button>
            </div>
          </div>
        )}
        {conn && (
          <div className="text-[11px] text-muted-foreground font-mono" dir="ltr">
            conn_id={conn.conn_id} home={conn.protocol_info.home ?? "-"} caps={Object.entries(conn.capabilities).filter(([, v]) => v).map(([k]) => k).join(",")}
          </div>
        )}
      </Section>

      <Section title="Local (manual list) / Remote">
        <p className="text-[11px] text-muted-foreground">
          There is no local-listing IPC yet, so the left pane shows names typed below (one per line, trailing / = folder).
          Set the left path to an absolute local folder: transfers use it as the local side. Drag entries between panes to upload / download.
        </p>
        <div className="h-72">
          <FileDualPane
            activePane={active}
            onActivePaneChange={setActive}
            onTransfer={onTransfer}
            left={{
              path: lPath,
              onNavigate: setLPath,
              entries: lEntries,
              selection: lSel,
              onSelectionChange: setLSel,
              onOpen: () => undefined,
              sort: lSort,
              onSortChange: setLSort,
              emptyText: "Type a local folder path above and entries below",
            }}
            right={{
              path: rPath,
              onNavigate: (p) => void loadRemote(p),
              entries: rEntries,
              selection: rSel,
              onSelectionChange: setRSel,
              onOpen: (e) => (e.isDir ? void loadRemote(e.path) : undefined),
              onGoUp: () => void loadRemote(parentPosix(rPath)),
              sort: rSort,
              onSortChange: setRSort,
              loading: rLoading,
              emptyText: connId ? "Empty" : "Not connected",
            }}
          />
        </div>
        <textarea className={textareaCls} rows={3} value={lText} onChange={(e) => setLText(e.target.value)} />
      </Section>

      <Section title="Remote operations (selection = right pane)">
        <Row>
          <Field label="Name / new name / path"><Input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="new-folder" /></Field>
          <Button size="sm" disabled={!connId || !newName} onClick={async () => { await run(() => RemoteService.mkdir(connId, joinPosix(rPath, newName), true)); void loadRemote(rPath); }}>mkdir</Button>
          <Button size="sm" variant="secondary" disabled={!connId || selectedPaths.length !== 1 || !newName} onClick={async () => { await run(() => RemoteService.rename(connId, selectedPaths[0], joinPosix(rPath, newName))); void loadRemote(rPath); }}>rename selected</Button>
          <Button size="sm" variant="destructive" disabled={!connId || selectedPaths.length === 0} onClick={async () => { await run(async () => { for (const p of selectedPaths) await RemoteService.delete(connId, p, true); }); void loadRemote(rPath); }}>delete selected</Button>
          <Button size="sm" variant="outline" disabled={!connId || selectedPaths.length !== 1} onClick={() => run(() => RemoteService.stat(connId, selectedPaths[0]))}>stat</Button>
          <Button size="sm" variant="outline" disabled={!connId || selectedPaths.length !== 1} onClick={() => run(() => RemoteService.readFile(connId, selectedPaths[0]).then((r) => ({ size: r.size, text: r.text ?? "(binary)" })))}>read</Button>
          <Button size="sm" variant="outline" disabled={!connId || selectedPaths.length !== 1} onClick={() => run(() => RemoteService.hash(connId, selectedPaths[0]))}>sha256</Button>
        </Row>
        <Row>
          <div className="flex-1 min-w-[260px]">
            <textarea className={textareaCls} rows={2} value={writeText} onChange={(e) => setWriteText(e.target.value)} />
          </div>
          <Button size="sm" disabled={!connId || !newName} onClick={async () => { await run(() => RemoteService.writeFile(connId, joinPosix(rPath, newName), writeText)); void loadRemote(rPath); }}>
            write file (name above)
          </Button>
        </Row>
        <Out value={out} />
      </Section>
    </>
  );
}

// ---------------------------------------------------------------- Transfers

function TransfersTab({ connId }: { connId: string }) {
  const { out, run, busy } = useAction();
  const [items, setItems] = useState<TransferItem[]>([]);
  const [live, setLive] = useState<Record<string, { bytes: number; total: number; speed: number; state: string }>>({});
  const [direction, setDirection] = useState<"up" | "down">("up");
  const [localPath, setLocalPath] = useState("");
  const [remotePath, setRemotePath] = useState("");
  const [recursive, setRecursive] = useState(false);
  const [overwrite, setOverwrite] = useState(true);
  const [conc, setConc] = useState("3");

  const refresh = useCallback(() => TransferService.list().then(setItems).catch(() => undefined), []);
  useEffect(() => {
    void refresh();
    const unlisten: (() => void)[] = [];
    let alive = true;
    TransferService.onProgress((e) => {
      setLive((p) => ({ ...p, [e.id]: { bytes: e.bytes, total: e.total, speed: e.speed_bps, state: e.state } }));
    }).then((f) => (alive ? unlisten.push(f) : f())).catch(() => undefined);
    TransferService.onDone(() => void refresh()).then((f) => (alive ? unlisten.push(f) : f())).catch(() => undefined);
    const t = setInterval(refresh, 2000);
    return () => {
      alive = false;
      unlisten.forEach((f) => f());
      clearInterval(t);
    };
  }, [refresh]);

  return (
    <>
      <Section title="Enqueue">
        <p className="text-[11px] text-muted-foreground">Connection: <span className="font-mono">{connId || "(connect in the Remote tab)"}</span>. Local path must be absolute.</p>
        <Row>
          <Field label="Direction">
            <select className="h-8 rounded-lg border border-input bg-background px-2 text-xs" value={direction} onChange={(e) => setDirection(e.target.value as "up" | "down")}>
              <option value="up">up (local to remote)</option>
              <option value="down">down (remote to local)</option>
            </select>
          </Field>
          <Field label="Local path"><Input value={localPath} onChange={(e) => setLocalPath(e.target.value)} placeholder="/path/to/local/file" /></Field>
          <Field label="Remote path"><Input value={remotePath} onChange={(e) => setRemotePath(e.target.value)} placeholder="/path/to/remote/file" /></Field>
        </Row>
        <Row>
          <label className="flex items-center gap-1 text-[11px]"><input type="checkbox" checked={recursive} onChange={(e) => setRecursive(e.target.checked)} /> recursive</label>
          <label className="flex items-center gap-1 text-[11px]"><input type="checkbox" checked={overwrite} onChange={(e) => setOverwrite(e.target.checked)} /> overwrite</label>
          <Button disabled={busy || !connId || !localPath || !remotePath} onClick={async () => { await run(() => TransferService.enqueue({ conn_id: connId, direction, local_path: localPath, remote_path: remotePath, recursive, overwrite })); void refresh(); }}>Enqueue</Button>
          <Field label="Concurrency (1-8)"><Input value={conc} onChange={(e) => setConc(e.target.value.replace(/\D/g, ""))} /></Field>
          <Button variant="secondary" onClick={() => run(() => TransferService.setConcurrency(Number(conc) || 3))}>Apply</Button>
          <Button variant="outline" onClick={async () => { await run(() => TransferService.clearFinished()); void refresh(); }}>Clear finished</Button>
        </Row>
        <Out value={out} />
      </Section>

      <Section title={`Queue (${items.length})`}>
        <table className="w-full text-xs">
          <thead className="text-muted-foreground text-left">
            <tr><th>Dir</th><th>Remote</th><th>State</th><th>Progress</th><th /></tr>
          </thead>
          <tbody>
            {items.map((it) => {
              const l = live[it.id];
              const bytes = l?.bytes ?? it.bytes;
              const total = l?.total ?? it.total;
              const state = (it.state === "done" || it.state === "failed" || it.state === "cancelled") ? it.state : l?.state ?? it.state;
              const pct = total > 0 ? Math.round((bytes / total) * 100) : 0;
              return (
                <tr key={it.id} className="border-t border-border/60">
                  <td className="py-1">{it.direction}</td>
                  <td className="font-mono max-w-[260px] truncate" title={it.remote_path}>{it.remote_path}</td>
                  <td><Badge variant={state === "done" ? "success" : state === "failed" ? "destructive" : "secondary"}>{state}</Badge></td>
                  <td className="w-48">
                    <div className="h-1.5 w-full rounded bg-muted overflow-hidden"><div className="h-full bg-primary" style={{ width: `${pct}%` }} /></div>
                    <span className="text-[10px] text-muted-foreground">{pct}% {l?.speed ? `${Math.round(l.speed / 1024)} KB/s` : ""} {it.error ?? ""}</span>
                  </td>
                  <td>
                    {(it.state === "queued" || it.state === "running") && (
                      <Button size="sm" variant="outline" onClick={async () => { await run(() => TransferService.cancel(it.id)); void refresh(); }}>Cancel</Button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </Section>
    </>
  );
}

// ---------------------------------------------------------------- Snapshots

function SnapshotsTab() {
  const { out, run, busy } = useAction();
  const [repo, setRepo] = useState("lab-repo");
  const [filesText, setFilesText] = useState("notes/a.txt=/path/to/local/a.txt");
  const [message, setMessage] = useState("lab commit");
  const [log, setLog] = useState<SnapshotLogEntry[]>([]);
  const [from, setFrom] = useState("HEAD~1");
  const [to, setTo] = useState("HEAD");
  const [diff, setDiff] = useState<SnapshotDiffResult | null>(null);
  const [sel, setSel] = useState<string | null>(null);
  const [mode, setMode] = useState<DiffMode>("unified");
  const [rCommit, setRCommit] = useState("HEAD");
  const [rPath, setRPath] = useState("notes/a.txt");
  const [rDest, setRDest] = useState("");

  const parseFiles = () =>
    filesText
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => {
        const i = l.indexOf("=");
        return { path: l.slice(0, i), localPath: l.slice(i + 1) };
      });
  const loadLog = async () => { const r = await run(() => SnapshotService.log(repo, 30)); if (r) setLog(r); };
  const selFile = diff?.files.find((f) => f.path === sel);

  return (
    <>
      <Section title="Repository and commit">
        <Row>
          <Field label="Repo (id or absolute path)"><Input value={repo} onChange={(e) => setRepo(e.target.value)} /></Field>
          <Button disabled={busy || !repo} onClick={() => run(() => SnapshotService.init(/^[A-Za-z0-9_.-]+$/.test(repo) ? { repoId: repo } : { repoPath: repo }))}>Init</Button>
        </Row>
        <Field label="Files: one per line, repo/path=/absolute/local/path">
          <textarea className={textareaCls} rows={3} value={filesText} onChange={(e) => setFilesText(e.target.value)} />
        </Field>
        <Row>
          <Field label="Message"><Input value={message} onChange={(e) => setMessage(e.target.value)} /></Field>
          <Button disabled={busy} onClick={async () => { await run(() => SnapshotService.commit(repo, parseFiles(), message, { metadata: { source: "core-lab" } })); void loadLog(); }}>Commit</Button>
          <Button variant="secondary" onClick={loadLog}>Log</Button>
        </Row>
        <div className="max-h-40 overflow-auto text-xs">
          {log.map((c) => (
            <div key={c.id} className="flex gap-2 border-t border-border/60 py-1 cursor-pointer hover:bg-muted/30" onClick={() => { setTo(c.id); }}>
              <span className="font-mono text-primary">{c.shortId}</span>
              <span className="flex-1 truncate">{c.message}</span>
              <span className="text-muted-foreground">{new Date(c.time * 1000).toLocaleString()}</span>
            </div>
          ))}
        </div>
        <Out value={out} />
      </Section>

      <Section title="Diff">
        <Row>
          <Field label="From (commit-ish or WORKDIR:/dir)"><Input value={from} onChange={(e) => setFrom(e.target.value)} /></Field>
          <Field label="To"><Input value={to} onChange={(e) => setTo(e.target.value)} /></Field>
          <Button onClick={async () => { const r = await run(() => SnapshotService.diff(repo, from, to)); if (r) { setDiff(r); setSel(r.files[0]?.path ?? null); } }}>Diff</Button>
        </Row>
        {diff && (
          <div className="flex gap-3">
            <div className="w-56 shrink-0 text-xs space-y-1">
              {diff.files.map((f) => (
                <div key={f.path} onClick={() => setSel(f.path)} className={`cursor-pointer rounded px-2 py-1 ${sel === f.path ? "bg-primary/15" : "hover:bg-muted/30"}`}>
                  <Badge variant={f.status === "added" ? "success" : f.status === "removed" ? "destructive" : "warning"}>{f.status}</Badge>{" "}
                  <span className="font-mono">{f.path}</span>
                </div>
              ))}
              {diff.truncated && <p className="text-amber-500">truncated</p>}
            </div>
            <div className="flex-1 min-w-0 max-h-96 overflow-auto">
              {selFile && (
                <DiffViewer
                  unifiedPatch={selFile.patch ?? undefined}
                  binary={selFile.binary || selFile.patch == null}
                  mode={mode}
                  onModeChange={setMode}
                  oldLabel={`${from}:${selFile.path}`}
                  newLabel={`${to}:${selFile.path}`}
                />
              )}
              {selFile?.patchSkipped && <p className="text-[11px] text-amber-500 mt-1">Patch skipped: {selFile.patchSkipped}</p>}
            </div>
          </div>
        )}
      </Section>

      <Section title="Restore file">
        <Row>
          <Field label="Commit"><Input value={rCommit} onChange={(e) => setRCommit(e.target.value)} /></Field>
          <Field label="Repo path"><Input value={rPath} onChange={(e) => setRPath(e.target.value)} /></Field>
          <Field label="Destination (absolute)"><Input value={rDest} onChange={(e) => setRDest(e.target.value)} placeholder="/path/to/restored.txt" /></Field>
          <Button disabled={!rDest} onClick={() => run(() => SnapshotService.restoreFile(repo, rCommit, rPath, rDest))}>Restore</Button>
        </Row>
      </Section>
    </>
  );
}

// ---------------------------------------------------------------- Hash / Zip

function HashZipTab() {
  const { out, run, busy } = useAction();
  const [path, setPath] = useState("");
  const [dirA, setDirA] = useState("");
  const [dirB, setDirB] = useState("");
  const [zipSrc, setZipSrc] = useState("");
  const [zipDest, setZipDest] = useState("");
  const [exZip, setExZip] = useState("");
  const [exDest, setExDest] = useState("");
  const [progress, setProgress] = useState<FsProgressEvent | null>(null);
  const opRef = useRef<string>("");

  useEffect(() => {
    let un: (() => void) | undefined;
    FsUtilService.onProgress((e) => { if (e.op_id === opRef.current) setProgress(e); }).then((f) => (un = f)).catch(() => undefined);
    return () => un?.();
  }, []);

  const withOp = <T,>(fn: (opId: string) => Promise<T>) => {
    const id = newOpId("lab");
    opRef.current = id;
    setProgress(null);
    return run(() => fn(id));
  };
  const pct = progress && progress.total > 0 ? Math.round((progress.done / progress.total) * 100) : 0;

  return (
    <>
      <Section title="Hash">
        <Row>
          <Field label="File or folder (absolute)"><Input value={path} onChange={(e) => setPath(e.target.value)} placeholder="/path/to/file-or-folder" /></Field>
          <Button disabled={busy || !path} onClick={() => withOp((op) => FsUtilService.hashFile(path, op))}>Hash file</Button>
          <Button disabled={busy || !path} variant="secondary" onClick={() => withOp((op) => FsUtilService.hashTree(path, { opId: op }).then((r) => ({ ...r, entries: r.entries.slice(0, 50) })))}>Hash tree</Button>
        </Row>
      </Section>
      <Section title="Compare trees (A = baseline)">
        <Row>
          <Field label="Folder A"><Input value={dirA} onChange={(e) => setDirA(e.target.value)} placeholder="/path/to/a" /></Field>
          <Field label="Folder B"><Input value={dirB} onChange={(e) => setDirB(e.target.value)} placeholder="/path/to/b" /></Field>
          <Button disabled={busy || !dirA || !dirB} onClick={() => withOp((op) => FsUtilService.compareTrees(dirA, dirB, { opId: op }))}>Compare</Button>
        </Row>
      </Section>
      <Section title="Zip / Unzip">
        <Row>
          <Field label="Source folder"><Input value={zipSrc} onChange={(e) => setZipSrc(e.target.value)} placeholder="/path/to/folder" /></Field>
          <Field label="Destination .zip"><Input value={zipDest} onChange={(e) => setZipDest(e.target.value)} placeholder="/path/to/out.zip" /></Field>
          <Button disabled={busy || !zipSrc || !zipDest} onClick={() => withOp((op) => FsUtilService.zipCreate(zipSrc, zipDest, { opId: op }))}>Zip</Button>
        </Row>
        <Row>
          <Field label="Zip file"><Input value={exZip} onChange={(e) => setExZip(e.target.value)} placeholder="/path/to/in.zip" /></Field>
          <Field label="Extract to"><Input value={exDest} onChange={(e) => setExDest(e.target.value)} placeholder="/path/to/folder" /></Field>
          <Button disabled={busy || !exZip || !exDest} onClick={() => withOp((op) => FsUtilService.zipExtract(exZip, exDest, { opId: op }))}>Unzip</Button>
          <Button variant="destructive" disabled={!busy} onClick={() => FsUtilService.cancel(opRef.current)}>Cancel op</Button>
        </Row>
        {progress && (
          <div>
            <div className="h-1.5 w-full rounded bg-muted overflow-hidden"><div className="h-full bg-primary" style={{ width: `${pct}%` }} /></div>
            <span className="text-[10px] text-muted-foreground">{progress.phase}: {pct}% ({progress.done} / {progress.total} bytes)</span>
          </div>
        )}
        <Out value={out} />
      </Section>
    </>
  );
}

// ---------------------------------------------------------------- Diff

function DiffTab() {
  const [a, setA] = useState("line one\nline two\nline three\n");
  const [b, setB] = useState("line one\nline 2\nline three\nline four\n");
  const [mode, setMode] = useState<DiffMode>("split");
  const [ws, setWs] = useState(false);
  return (
    <Section title="Paste two texts">
      <div className="grid grid-cols-2 gap-3">
        <textarea className={textareaCls} rows={8} value={a} onChange={(e) => setA(e.target.value)} />
        <textarea className={textareaCls} rows={8} value={b} onChange={(e) => setB(e.target.value)} />
      </div>
      <DiffViewer
        oldText={a}
        newText={b}
        mode={mode}
        onModeChange={setMode}
        ignoreWhitespace={ws}
        onIgnoreWhitespaceChange={setWs}
        oldLabel="Original"
        newLabel="Modified"
      />
    </Section>
  );
}

// ---------------------------------------------------------------- Terminal

const DEFAULT_POLICY = JSON.stringify(
  {
    rules: [
      { type: "exact", line: "ls" },
      { type: "command", command: "ls", args: ["-la", "<path-under:/var/www>"] },
      { type: "exact", line: "git pull" },
    ],
    max_line_len: 512,
  },
  null,
  2
);

interface DeniedItem { term_id: string; line: string; reason_code: string; message: string; at: number }

function TerminalTab() {
  const { toast } = useNotificationStore();
  const [secrets, setSecrets] = useState<SecretInfo[]>([]);
  const [host, setHost] = useState("");
  const [port, setPort] = useState("22");
  const [username, setUsername] = useState("");
  const [auth, setAuth] = useState<"password" | "key">("password");
  const [secretRef, setSecretRef] = useState("");
  const [policyText, setPolicyText] = useState(DEFAULT_POLICY);
  const [termId, setTermId] = useState("");
  const [state, setState] = useState("closed");
  const [opening, setOpening] = useState(false);
  const [status, setStatus] = useState<string>("");
  const [denied, setDenied] = useState<DeniedItem[]>([]);
  const [trustPrompt, setTrustPrompt] = useState<{ err: RemoteError; resolve: (ok: boolean) => void } | null>(null);

  const termRef = useRef<TerminalHandle>(null);
  const termIdRef = useRef("");
  const pendingRef = useRef<Map<string, Uint8Array[]>>(new Map());
  const sizeRef = useRef({ cols: 80, rows: 24 });

  // exec
  const [cmd, setCmd] = useState("ls");
  const [execId, setExecId] = useState("");
  const [execRunning, setExecRunning] = useState(false);
  const [execOut, setExecOut] = useState<Record<string, string>>({});
  const [execDone, setExecDone] = useState<Record<string, string>>({});
  const [execErr, setExecErr] = useState("");

  // audit
  const [audit, setAudit] = useState<AuditEntry[]>([]);

  useEffect(() => {
    VaultService.list().then(setSecrets).catch(() => setSecrets([]));
  }, []);

  // Subscribe ONCE to all terminals/execs; events may arrive before open()/exec() resolves.
  useEffect(() => {
    const unlisten: (() => void)[] = [];
    let alive = true;
    const keep = (p: Promise<() => void>) => p.then((f) => (alive ? unlisten.push(f) : f())).catch(() => undefined);
    const dec = new Map<string, TextDecoder>();
    const decode = (key: string, bytes: Uint8Array) => {
      let d = dec.get(key);
      if (!d) dec.set(key, (d = new TextDecoder()));
      return d.decode(bytes, { stream: true });
    };
    keep(TerminalService.onData((e) => {
      if (e.term_id === termIdRef.current) termRef.current?.write(e.bytes);
      else {
        const arr = pendingRef.current.get(e.term_id) ?? [];
        if (arr.length < 500) arr.push(e.bytes);
        pendingRef.current.set(e.term_id, arr);
      }
    }));
    keep(TerminalService.onDenied((e) => setDenied((p) => [{ ...e, at: Date.now() }, ...p].slice(0, 100))));
    keep(TerminalService.onState((e) => { if (e.term_id === termIdRef.current || !termIdRef.current) setState(e.state); }));
    keep(TerminalService.onExit((e) => {
      if (e.term_id === termIdRef.current) {
        setState("closed");
        setStatus(`exited${e.code != null ? ` (code ${e.code})` : ""}`);
      }
    }));
    keep(TerminalService.onExecData((e) => {
      const t = decode(e.exec_id + e.stream, e.bytes);
      setExecOut((p) => ({ ...p, [e.exec_id]: (p[e.exec_id] ?? "") + (e.stream === "stderr" ? `[stderr] ${t}` : t) }));
    }));
    keep(TerminalService.onExecDone((e) => {
      setExecDone((p) => ({
        ...p,
        [e.exec_id]: `exit=${e.exit_status ?? "-"}${e.timed_out ? " TIMED_OUT" : ""}${e.truncated ? " TRUNCATED" : ""}${e.error ? ` error=${e.error}` : ""}`,
      }));
    }));
    return () => {
      alive = false;
      unlisten.forEach((f) => f());
      const id = termIdRef.current;
      if (id) void TerminalService.close(id).catch(() => undefined);
    };
  }, []);

  const profile = (): SshProfile => ({
    host: host.trim(),
    port: port ? Number(port) : undefined,
    username,
    auth,
    secret_ref: secretRef || undefined,
  });

  /** Runs `fn`; on HOSTKEY_UNKNOWN/CHANGED asks the user, trusts via ssh_trust_host and retries once. */
  const withTrust = async <T,>(fn: () => Promise<T>): Promise<T> => {
    try {
      return await fn();
    } catch (e) {
      const err = parseRemoteError(e);
      if ((err.code !== "HOSTKEY_UNKNOWN" && err.code !== "HOSTKEY_CHANGED") || !err.fingerprint) throw e;
      const ok = await new Promise<boolean>((resolve) => setTrustPrompt({ err, resolve }));
      setTrustPrompt(null);
      if (!ok) throw e;
      await RemoteService.trustHost(host.trim(), Number(port) || 22, err.fingerprint);
      return await fn();
    }
  };

  const parsePolicy = () => {
    const t = policyText.trim();
    return t ? (JSON.parse(t) as GuardPolicy) : undefined;
  };

  const open = async () => {
    let policy: GuardPolicy | undefined;
    try {
      policy = parsePolicy();
    } catch (e) {
      setStatus(`Policy JSON invalid: ${(e as Error).message}`);
      return;
    }
    setOpening(true);
    setStatus("");
    pendingRef.current.clear();
    termRef.current?.clear();
    try {
      const { cols, rows } = sizeRef.current;
      const r = await withTrust(() => TerminalService.open({ profile: profile(), policy, cols, rows, user_label: "core-lab" }));
      termIdRef.current = r.term_id;
      setTermId(r.term_id);
      setState("ready");
      for (const b of pendingRef.current.get(r.term_id) ?? []) termRef.current?.write(b);
      pendingRef.current.clear();
      termRef.current?.fit();
      void TerminalService.resize(r.term_id, sizeRef.current.cols, sizeRef.current.rows).catch(() => undefined);
      termRef.current?.focus();
    } catch (e) {
      setStatus(`ERROR: ${errText(e)}`);
      toast({ type: "error", title: "Terminal", message: errText(e) });
    } finally {
      setOpening(false);
    }
  };

  const close = async () => {
    const id = termIdRef.current;
    if (!id) return;
    termIdRef.current = "";
    setTermId("");
    setState("closed");
    await TerminalService.close(id).catch((e) => setStatus(`ERROR: ${errText(e)}`));
  };

  const applyPolicy = async () => {
    try {
      await TerminalService.setPolicy(termId, parsePolicy());
      setStatus("Policy updated");
    } catch (e) {
      setStatus(`ERROR: ${e instanceof SyntaxError ? e.message : errText(e)}`);
    }
  };

  const runExec = async () => {
    let policy: GuardPolicy | undefined;
    try {
      policy = parsePolicy();
    } catch (e) {
      setExecErr(`Policy JSON invalid: ${(e as Error).message}`);
      return;
    }
    setExecErr("");
    setExecId("");
    setExecRunning(true);
    try {
      const r = await withTrust(() => TerminalService.exec({ profile: profile(), command: cmd, policy, user_label: "core-lab" }));
      setExecId(r.exec_id);
    } catch (e) {
      setExecErr(`ERROR: ${errText(e)}`);
      setExecRunning(false);
    }
  };

  // exec finished -> stop "running"
  useEffect(() => {
    if (execId && execDone[execId]) setExecRunning(false);
  }, [execId, execDone]);

  const refreshAudit = useCallback(async () => {
    try {
      setAudit(await TerminalService.auditList({ limit: 100 }));
    } catch (e) {
      toast({ type: "error", title: "Audit", message: errText(e) });
    }
  }, [toast]);
  useEffect(() => { void refreshAudit(); }, [refreshAudit]);

  const selCls = "h-8 rounded-lg border border-input bg-background px-2 text-xs";
  const isOpen = !!termId;

  return (
    <>
      <Section title="SSH profile and policy">
        <Row>
          <Field label="Host"><Input value={host} onChange={(e) => setHost(e.target.value)} placeholder="host.example.com" /></Field>
          <Field label="Port"><Input value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, ""))} /></Field>
          <Field label="Username"><Input value={username} onChange={(e) => setUsername(e.target.value)} /></Field>
          <Field label="Auth">
            <select className={selCls} value={auth} onChange={(e) => setAuth(e.target.value as "password" | "key")}>
              <option value="password">password</option>
              <option value="key">key</option>
            </select>
          </Field>
          <Field label="Vault secret id">
            <Input list="lab-term-secret-ids" value={secretRef} onChange={(e) => setSecretRef(e.target.value)} />
            <datalist id="lab-term-secret-ids">{secrets.map((s) => <option key={s.id} value={s.id} />)}</datalist>
          </Field>
        </Row>
        <Field label="GuardPolicy JSON (empty = deny everything)">
          <textarea dir="ltr" className={textareaCls} rows={9} value={policyText} onChange={(e) => setPolicyText(e.target.value)} />
        </Field>
        <Row>
          <Button disabled={opening || isOpen || !host || !username} onClick={open}>Open</Button>
          <Button variant="outline" disabled={!isOpen} onClick={close}>Close</Button>
          <Button variant="secondary" disabled={!isOpen} onClick={applyPolicy}>Apply policy</Button>
          <Button size="sm" variant="ghost" onClick={() => VaultService.list().then(setSecrets).catch(() => undefined)}>Reload secrets</Button>
          <Badge variant={state === "ready" || state === "running" ? "success" : state === "error" ? "destructive" : "secondary"}>{state}</Badge>
          {termId && <span className="text-[11px] font-mono text-muted-foreground" dir="ltr">{termId}</span>}
        </Row>
        {trustPrompt && (
          <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs space-y-2">
            <p className="font-medium">
              {trustPrompt.err.code === "HOSTKEY_CHANGED"
                ? "WARNING: the host key CHANGED (possible man-in-the-middle)."
                : "Unknown host key (first contact)."}
            </p>
            <p dir="ltr" className="font-mono break-all">
              {trustPrompt.err.fingerprint}
              {trustPrompt.err.expectedFingerprint ? ` (stored: ${trustPrompt.err.expectedFingerprint})` : ""}
            </p>
            <div className="flex gap-2">
              <Button size="sm" onClick={() => trustPrompt.resolve(true)}>Trust and continue</Button>
              <Button size="sm" variant="outline" onClick={() => trustPrompt.resolve(false)}>Reject</Button>
            </div>
          </div>
        )}
        {status && <Out value={status} />}
      </Section>

      <Section title="Interactive terminal">
        <div className="h-72 rounded-lg border border-border overflow-hidden">
          <Terminal
            ref={termRef}
            ariaLabel="Core Lab terminal"
            onData={(d) => { const id = termIdRef.current; if (id) void TerminalService.write(id, d).catch(() => undefined); }}
            onResize={(s) => {
              sizeRef.current = s;
              const id = termIdRef.current;
              if (id) void TerminalService.resize(id, s.cols, s.rows).catch(() => undefined);
            }}
          />
        </div>
      </Section>

      <Section title={`Denied feed (${denied.length})`}>
        <div className="max-h-40 overflow-auto text-xs font-mono" dir="ltr">
          {denied.length === 0 && <p className="text-muted-foreground">No denied lines yet.</p>}
          {denied.map((d, i) => (
            <div key={i} className="border-t border-border/60 py-1">
              <span className="text-muted-foreground">{new Date(d.at).toLocaleTimeString()}</span>{" "}
              <Badge variant="destructive">{d.reason_code}</Badge> <span>{d.line}</span>{" "}
              <span className="text-muted-foreground">{d.message}</span>
            </div>
          ))}
        </div>
      </Section>

      <Section title="One-shot exec">
        <Row>
          <Field label="Command"><Input dir="ltr" value={cmd} onChange={(e) => setCmd(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && !execRunning && host && username && cmd) void runExec(); }} /></Field>
          <Button disabled={execRunning || !host || !username || !cmd} onClick={runExec}>Run</Button>
          <Button variant="outline" disabled={!execRunning || !execId} onClick={() => TerminalService.execCancel(execId).catch((e) => setExecErr(`ERROR: ${errText(e)}`))}>Cancel</Button>
        </Row>
        {execErr && <p dir="ltr" className={`text-xs font-mono ${execErr.includes("DENIED") ? "text-destructive" : "text-amber-500"}`}>{execErr}</p>}
        <Out value={execId ? `${execOut[execId] ?? ""}${execDone[execId] ? `\n--- ${execDone[execId]}` : ""}` || "(running...)" : undefined} />
      </Section>

      <Section title={`Audit (${audit.length})`}>
        <Row><Button size="sm" variant="outline" onClick={refreshAudit}>Refresh</Button></Row>
        <div className="max-h-72 overflow-auto">
          <table className="w-full text-xs" dir="ltr">
            <thead className="text-muted-foreground text-left">
              <tr><th>Time</th><th>Source</th><th>Verdict</th><th>Reason</th><th>Line</th></tr>
            </thead>
            <tbody>
              {audit.map((a, i) => (
                <tr key={i} className="border-t border-border/60">
                  <td className="py-1 whitespace-nowrap">{a.ts}</td>
                  <td>{a.source}</td>
                  <td><Badge variant={a.verdict === "allow" ? "success" : "destructive"}>{a.verdict}</Badge></td>
                  <td className="font-mono">{a.reason_code ?? ""}</td>
                  <td className="font-mono break-all">{a.line}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>
    </>
  );
}

// ---------------------------------------------------------------- page

export const CoreLab = () => {
  const [tab, setTab] = useState<TabId>("vault");
  const [connId, setConnId] = useState("");

  // Show transfers in the Task Queue pages while the lab is open (also started globally by App).
  useEffect(() => startTransferTaskBridge(), []);

  return (
    <div className="p-5 max-w-6xl mx-auto">
      <div className="mb-4">
        <h2 className="text-base font-bold">Core Lab</h2>
        <p className="text-xs text-muted-foreground">Dev-only manual tests for vault, remote, transfers, snapshots, hash/zip and diff.</p>
      </div>
      <div className="flex flex-wrap gap-1 mb-4 border-b border-border">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-3 py-1.5 text-xs font-medium rounded-t-lg cursor-pointer ${tab === t.id ? "bg-primary/15 text-primary border-b-2 border-primary" : "text-muted-foreground hover:text-foreground"}`}
          >
            {t.label}
          </button>
        ))}
      </div>
      {tab === "vault" && <VaultTab />}
      {tab === "remote" && <RemoteTab connId={connId} setConnId={setConnId} />}
      {tab === "transfers" && <TransfersTab connId={connId} />}
      {tab === "snapshots" && <SnapshotsTab />}
      {tab === "hashzip" && <HashZipTab />}
      {tab === "diff" && <DiffTab />}
      {tab === "terminal" && <TerminalTab />}
    </div>
  );
};

export default CoreLab;
