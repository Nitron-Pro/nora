import {
  useCallback, useEffect, useMemo, useRef, useState,
  type DragEvent, type KeyboardEvent, type MouseEvent,
} from "react";
import { File as FileIcon, Folder, ArrowUp, ArrowDown, Loader2 } from "lucide-react";
import { useSettingsStore } from "@/core/store/settingsStore";
import type { TranslationKey } from "@/core/i18n/translations";
import { cn } from "@/core/utils/cn";
import { formatBytes, formatDate } from "@/core/utils/format";

export interface FileEntry {
  name: string;
  path: string;
  isDir: boolean;
  size?: number;
  /** Epoch milliseconds or ISO string. */
  modified?: number | string;
  mode?: string;
  owner?: string;
}

export type FileColumnKey = "name" | "size" | "modified" | "mode" | "owner";
export interface FileSort { key: FileColumnKey; dir: "asc" | "desc" }
export interface FileColumn {
  key: FileColumnKey;
  /** Override the translated header label. */
  label?: string;
  /** Fixed width in px (ignored for the name column, which flexes). */
  width?: number;
}

export const DEFAULT_FILE_COLUMNS: FileColumn[] = [
  { key: "name" },
  { key: "size", width: 90 },
  { key: "modified", width: 150 },
];

export interface FileDragPayload {
  sourceId: string;
  entries: FileEntry[];
}

export interface FileDropInfo extends FileDragPayload {
  /** Folder the entries were dropped on, or the list's current path. */
  targetPath: string;
}

export interface VirtualFileListProps {
  entries: FileEntry[];
  /** Selected entry paths. */
  selection: ReadonlySet<string>;
  onSelectionChange: (selection: Set<string>) => void;
  onOpen: (entry: FileEntry) => void;
  onContextMenu?: (entry: FileEntry | null, e: MouseEvent) => void;
  /** Backspace handler (navigate to parent). */
  onGoUp?: () => void;
  sort: FileSort;
  onSortChange: (sort: FileSort) => void;
  /** Set when the parent sorts entries itself (e.g. server side). */
  presorted?: boolean;
  columns?: FileColumn[];
  loading?: boolean;
  emptyText?: string;
  /** MIME-like key used for the internal drag payload. */
  dragType: string;
  /** Unique id of this list; written into drag payloads. */
  id?: string;
  /** Folder shown by this list; default drop target. */
  path?: string;
  onDropEntries?: (info: FileDropInfo) => void;
  /** OS files dropped from the file manager (HTML5 path; may lack real paths in Tauri). */
  onDropFiles?: (files: File[], targetPath: string | undefined) => void;
  rowHeight?: number;
  className?: string;
  ariaLabel?: string;
}

const OVERSCAN = 8;
const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });

function modifiedMs(v: FileEntry["modified"]): number {
  if (v == null) return 0;
  return typeof v === "number" ? v : new Date(v).getTime() || 0;
}

export function sortEntries(entries: FileEntry[], sort: FileSort): FileEntry[] {
  const m = sort.dir === "asc" ? 1 : -1;
  const cmp = (a: FileEntry, b: FileEntry): number => {
    switch (sort.key) {
      case "size": return (a.size ?? 0) - (b.size ?? 0);
      case "modified": return modifiedMs(a.modified) - modifiedMs(b.modified);
      case "mode": return collator.compare(a.mode ?? "", b.mode ?? "");
      case "owner": return collator.compare(a.owner ?? "", b.owner ?? "");
      default: return collator.compare(a.name, b.name);
    }
  };
  // Folders always first regardless of direction.
  return [...entries].sort((a, b) =>
    a.isDir !== b.isDir ? (a.isDir ? -1 : 1) : m * cmp(a, b) || collator.compare(a.name, b.name)
  );
}

const HEADER_KEYS: Record<FileColumnKey, TranslationKey> = {
  name: "fileName", size: "fileSize", modified: "fileModified", mode: "fileMode", owner: "fileOwner",
};

export function VirtualFileList({
  entries, selection, onSelectionChange, onOpen, onContextMenu, onGoUp,
  sort, onSortChange, presorted = false, columns = DEFAULT_FILE_COLUMNS,
  loading = false, emptyText, dragType, id = "list", path, onDropEntries, onDropFiles,
  rowHeight = 28, className, ariaLabel,
}: VirtualFileListProps) {
  const t = useSettingsStore((s) => s.t);
  const language = useSettingsStore((s) => s.language);
  const mime = dragType.toLowerCase(); // DataTransfer.types is lowercased by browsers
  const scrollRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewH, setViewH] = useState(400);
  const [focusIdx, setFocusIdx] = useState(0);
  const [dropOver, setDropOver] = useState<number | "list" | null>(null);
  const anchor = useRef(0);
  const typeBuf = useRef({ text: "", at: 0 });
  const listId = useRef(`vfl-${Math.random().toString(36).slice(2, 8)}`).current;

  const rows = useMemo(() => (presorted ? entries : sortEntries(entries, sort)), [entries, sort, presorted]);
  const total = rows.length;

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    setViewH(el.clientHeight);
    const ro = new ResizeObserver(() => setViewH(el.clientHeight));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // New folder: back to top.
  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = 0;
    setScrollTop(0);
    setFocusIdx(0);
    anchor.current = 0;
  }, [path]);

  useEffect(() => { if (focusIdx >= total && total > 0) setFocusIdx(total - 1); }, [total, focusIdx]);

  const start = Math.max(0, Math.floor(scrollTop / rowHeight) - OVERSCAN);
  const end = Math.min(total, Math.ceil((scrollTop + viewH) / rowHeight) + OVERSCAN);
  const pageSize = Math.max(1, Math.floor(viewH / rowHeight) - 1);

  const ensureVisible = useCallback((i: number) => {
    const el = scrollRef.current;
    if (!el) return;
    const top = i * rowHeight;
    if (top < el.scrollTop) el.scrollTop = top;
    else if (top + rowHeight > el.scrollTop + el.clientHeight) el.scrollTop = top + rowHeight - el.clientHeight;
  }, [rowHeight]);

  const rangeSet = (a: number, b: number, base?: ReadonlySet<string>) => {
    const s = new Set(base ?? []);
    for (let i = Math.min(a, b); i <= Math.max(a, b); i++) s.add(rows[i].path);
    return s;
  };

  const moveFocus = (i: number, e: { shiftKey: boolean; ctrlKey: boolean; metaKey: boolean }) => {
    if (!total) return;
    const idx = Math.max(0, Math.min(total - 1, i));
    setFocusIdx(idx);
    ensureVisible(idx);
    if (e.shiftKey) onSelectionChange(rangeSet(anchor.current, idx));
    else if (!(e.ctrlKey || e.metaKey)) {
      anchor.current = idx;
      onSelectionChange(new Set([rows[idx].path]));
    }
  };

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    switch (e.key) {
      case "ArrowDown": e.preventDefault(); moveFocus(focusIdx + 1, e); return;
      case "ArrowUp": e.preventDefault(); moveFocus(focusIdx - 1, e); return;
      case "PageDown": e.preventDefault(); moveFocus(focusIdx + pageSize, e); return;
      case "PageUp": e.preventDefault(); moveFocus(focusIdx - pageSize, e); return;
      case "Home": e.preventDefault(); moveFocus(0, e); return;
      case "End": e.preventDefault(); moveFocus(total - 1, e); return;
      case "Enter": if (rows[focusIdx]) { e.preventDefault(); onOpen(rows[focusIdx]); } return;
      case "Backspace": e.preventDefault(); onGoUp?.(); return;
      case " ":
        if ((e.ctrlKey || e.metaKey) && rows[focusIdx]) {
          e.preventDefault();
          const s = new Set(selection);
          const p = rows[focusIdx].path;
          if (s.has(p)) s.delete(p); else s.add(p);
          onSelectionChange(s);
        }
        return;
      case "a":
      case "A":
        if (e.ctrlKey || e.metaKey) { e.preventDefault(); onSelectionChange(new Set(rows.map((r) => r.path))); }
        return;
      case "Escape": onSelectionChange(new Set()); return;
    }
    // Type-ahead: printable characters jump to the next matching name.
    if (e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {
      const now = Date.now();
      const b = typeBuf.current;
      b.text = now - b.at > 700 ? e.key : b.text + e.key;
      b.at = now;
      const q = b.text.toLowerCase();
      const from = b.text.length === 1 ? focusIdx + 1 : focusIdx;
      for (let k = 0; k < total; k++) {
        const i = (from + k) % total;
        if (rows[i].name.toLowerCase().startsWith(q)) { moveFocus(i, { shiftKey: false, ctrlKey: false, metaKey: false }); break; }
      }
    }
  };

  const onRowClick = (i: number, e: MouseEvent) => {
    scrollRef.current?.focus({ preventScroll: true });
    setFocusIdx(i);
    if (e.shiftKey) onSelectionChange(rangeSet(anchor.current, i));
    else if (e.ctrlKey || e.metaKey) {
      const s = new Set(selection);
      const p = rows[i].path;
      if (s.has(p)) s.delete(p); else s.add(p);
      anchor.current = i;
      onSelectionChange(s);
    } else {
      anchor.current = i;
      onSelectionChange(new Set([rows[i].path]));
    }
  };

  const dragEntries = (i: number): FileEntry[] => {
    const row = rows[i];
    if (!selection.has(row.path)) return [row];
    return rows.filter((r) => selection.has(r.path));
  };

  const onDragStart = (i: number, e: DragEvent) => {
    const list = dragEntries(i);
    if (!selection.has(rows[i].path)) onSelectionChange(new Set([rows[i].path]));
    const payload: FileDragPayload = { sourceId: id, entries: list };
    e.dataTransfer.setData(mime, JSON.stringify(payload));
    e.dataTransfer.effectAllowed = "copyMove";
    // Small badge as drag preview showing what is being dragged.
    const ghost = document.createElement("div");
    ghost.textContent = list.length > 1 ? t("fileItemsSelected").replace("{n}", String(list.length)) : list[0].name;
    ghost.className = "fixed -top-96 rounded-md border bg-popover px-2 py-1 text-xs text-popover-foreground shadow";
    document.body.appendChild(ghost);
    e.dataTransfer.setDragImage(ghost, 8, 8);
    setTimeout(() => ghost.remove(), 0);
  };

  const accepts = (e: DragEvent) =>
    Array.from(e.dataTransfer.types).includes(mime) ||
    (!!onDropFiles && Array.from(e.dataTransfer.types).includes("Files"));

  const onDragOverRow = (i: number | "list", e: DragEvent) => {
    if (!accepts(e)) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = "copy";
    setDropOver(i);
  };

  const onDrop = (target: number | "list", e: DragEvent) => {
    setDropOver(null);
    if (!accepts(e)) return;
    e.preventDefault();
    e.stopPropagation();
    const folder = target !== "list" && rows[target].isDir ? rows[target].path : path;
    const raw = e.dataTransfer.getData(mime);
    if (raw) {
      try {
        const p = JSON.parse(raw) as FileDragPayload;
        // Dropping a folder (or selection) onto itself is meaningless.
        if (folder && p.entries.some((x) => x.path === folder)) return;
        if (folder) onDropEntries?.({ ...p, targetPath: folder });
      } catch { /* ignore malformed payload */ }
    } else if (e.dataTransfer.files.length) {
      onDropFiles?.(Array.from(e.dataTransfer.files), folder);
    }
  };

  const cols = columns.length ? columns : DEFAULT_FILE_COLUMNS;
  const gridCols = cols
    .map((c) => (c.key === "name" ? "minmax(0,1fr)" : `${c.width ?? 100}px`))
    .join(" ");

  const cell = (c: FileColumn, r: FileEntry) => {
    switch (c.key) {
      case "name":
        return (
          <span key="name" className="flex min-w-0 items-center gap-2">
            {r.isDir ? <Folder className="h-4 w-4 shrink-0 text-primary" /> : <FileIcon className="h-4 w-4 shrink-0 text-muted-foreground" />}
            <span dir="auto" className="truncate">{r.name}</span>
          </span>
        );
      case "size": return <span key="size" dir="ltr" className="truncate text-end tabular-nums text-muted-foreground">{r.isDir ? "" : formatBytes(r.size)}</span>;
      case "modified": return <span key="modified" dir="ltr" className="truncate text-muted-foreground">{formatDate(r.modified, language)}</span>;
      case "mode": return <span key="mode" dir="ltr" className="truncate font-mono text-muted-foreground">{r.mode ?? ""}</span>;
      case "owner": return <span key="owner" className="truncate text-muted-foreground">{r.owner ?? ""}</span>;
    }
  };

  const visible = [];
  for (let i = start; i < end; i++) {
    const r = rows[i];
    const selected = selection.has(r.path);
    visible.push(
      <div
        key={r.path}
        id={`${listId}-${i}`}
        role="option"
        aria-selected={selected}
        aria-setsize={total}
        aria-posinset={i + 1}
        draggable
        onClick={(e) => onRowClick(i, e)}
        onDoubleClick={() => onOpen(r)}
        onContextMenu={(e) => {
          if (!onContextMenu) return;
          e.preventDefault();
          if (!selected) { onSelectionChange(new Set([r.path])); anchor.current = i; }
          setFocusIdx(i);
          onContextMenu(r, e);
        }}
        onDragStart={(e) => onDragStart(i, e)}
        onDragOver={(e) => onDragOverRow(i, e)}
        onDragLeave={() => setDropOver((d) => (d === i ? null : d))}
        onDrop={(e) => onDrop(i, e)}
        style={{ top: i * rowHeight, height: rowHeight, gridTemplateColumns: gridCols }}
        className={cn(
          "absolute inset-x-0 grid cursor-default items-center gap-2 px-3 text-xs",
          selected ? "bg-accent text-accent-foreground" : "hover:bg-muted/60",
          i === focusIdx && "outline outline-1 -outline-offset-1 outline-ring/60",
          dropOver === i && r.isDir && "bg-primary/20 ring-1 ring-inset ring-primary"
        )}
      >
        {cols.map((c) => cell(c, r))}
      </div>
    );
  }

  const SortIcon = sort.dir === "asc" ? ArrowUp : ArrowDown;

  return (
    <div
      dir={language === "fa" ? "rtl" : "ltr"}
      className={cn("flex h-full min-h-0 flex-col overflow-hidden rounded-md border bg-card text-card-foreground", className)}
    >
      <div
        className="grid shrink-0 items-center gap-2 border-b bg-muted/40 px-3 text-[11px] font-medium text-muted-foreground"
        style={{ gridTemplateColumns: gridCols, height: rowHeight }}
      >
        {cols.map((c) => (
          <button
            key={c.key}
            type="button"
            onClick={() => onSortChange({ key: c.key, dir: sort.key === c.key && sort.dir === "asc" ? "desc" : "asc" })}
            aria-label={`${c.label ?? t(HEADER_KEYS[c.key])}${sort.key === c.key ? ` (${t(sort.dir === "asc" ? "fileSortAsc" : "fileSortDesc")})` : ""}`}
            className={cn("flex min-w-0 items-center gap-1 hover:text-foreground", c.key !== "name" && "justify-end")}
          >
            <span className="truncate">{c.label ?? t(HEADER_KEYS[c.key])}</span>
            {sort.key === c.key && <SortIcon className="h-3 w-3 shrink-0" />}
          </button>
        ))}
      </div>
      <div
        ref={scrollRef}
        role="listbox"
        aria-multiselectable="true"
        aria-label={ariaLabel ?? t("fileName")}
        aria-busy={loading}
        aria-activedescendant={total ? `${listId}-${focusIdx}` : undefined}
        tabIndex={0}
        onKeyDown={onKeyDown}
        onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
        onContextMenu={(e) => {
          if (e.target === e.currentTarget && onContextMenu) { e.preventDefault(); onContextMenu(null, e); }
        }}
        onClick={(e) => { if (e.target === e.currentTarget) onSelectionChange(new Set()); }}
        onDragOver={(e) => onDragOverRow("list", e)}
        onDragLeave={(e) => { if (e.currentTarget === e.target) setDropOver(null); }}
        onDrop={(e) => onDrop("list", e)}
        className={cn(
          "relative min-h-0 flex-1 overflow-y-auto overflow-x-hidden outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-ring",
          dropOver === "list" && "ring-1 ring-inset ring-primary"
        )}
      >
        <div style={{ height: total * rowHeight }} className="relative w-full">
          {visible}
        </div>
        {loading && (
          <div role="status" className="absolute inset-0 flex items-center justify-center gap-2 bg-background/60 text-xs text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> {t("fileLoading")}
          </div>
        )}
        {!loading && total === 0 && (
          <div className="absolute inset-0 flex items-center justify-center p-4 text-center text-xs text-muted-foreground pointer-events-none">
            {emptyText ?? t("fileEmpty")}
          </div>
        )}
      </div>
      {selection.size > 0 && (
        <div className="shrink-0 border-t bg-muted/30 px-3 py-1 text-[11px] text-muted-foreground">
          {t("fileItemsSelected").replace("{n}", String(selection.size))}
        </div>
      )}
    </div>
  );
}

export default VirtualFileList;
