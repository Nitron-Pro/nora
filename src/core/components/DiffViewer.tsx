import { useMemo, useState, type ReactNode } from "react";
import { diffLines, diffWordsWithSpace } from "diff";
import { Columns2, Rows2, ChevronsUpDown, FileWarning } from "lucide-react";
import { useSettingsStore } from "@/core/store/settingsStore";
import { cn } from "@/core/utils/cn";

export type DiffMode = "split" | "unified";

export interface DiffViewerProps {
  oldText?: string;
  newText?: string;
  /** Pre-computed unified patch (e.g. `git diff` output). Takes precedence over old/newText. */
  unifiedPatch?: string;
  mode: DiffMode;
  /** When provided the toolbar toggle becomes active and reports the new mode. */
  onModeChange?: (mode: DiffMode) => void;
  ignoreWhitespace?: boolean;
  onIgnoreWhitespaceChange?: (v: boolean) => void;
  oldLabel: string;
  newLabel: string;
  binary?: boolean;
  /** Unchanged lines kept around each change before folding. Default 3. */
  contextLines?: number;
  /** Above this many lines per side the input is truncated. Default 5000. */
  maxLines?: number;
  className?: string;
}

type LineType = "ctx" | "add" | "del";
interface Seg { text: string; changed: boolean }
interface DLine {
  type: LineType;
  oldNo?: number;
  newNo?: number;
  text: string;
  segs?: Seg[];
}
type Item =
  | { kind: "line"; line: DLine }
  | { kind: "fold"; id: number; lines: DLine[] }
  | { kind: "hunk"; header: string };

const MAX_INTRA_LEN = 600;

function splitLines(s: string): string[] {
  if (s === "") return [];
  const parts = s.replace(/\r\n/g, "\n").split("\n");
  if (parts[parts.length - 1] === "") parts.pop();
  return parts;
}

/** Add word-level segments to paired del/add lines inside one change block. */
function applyIntraLine(block: DLine[]) {
  const dels = block.filter((l) => l.type === "del");
  const adds = block.filter((l) => l.type === "add");
  const n = Math.min(dels.length, adds.length);
  for (let i = 0; i < n; i++) {
    const a = dels[i];
    const b = adds[i];
    if (a.text.length > MAX_INTRA_LEN || b.text.length > MAX_INTRA_LEN) continue;
    const parts = diffWordsWithSpace(a.text, b.text);
    a.segs = [];
    b.segs = [];
    for (const p of parts) {
      if (p.added) b.segs.push({ text: p.value, changed: true });
      else if (p.removed) a.segs.push({ text: p.value, changed: true });
      else {
        a.segs.push({ text: p.value, changed: false });
        b.segs.push({ text: p.value, changed: false });
      }
    }
  }
}

function flushBlock(out: DLine[], block: DLine[]) {
  if (!block.length) return;
  applyIntraLine(block);
  out.push(...block.filter((l) => l.type === "del"), ...block.filter((l) => l.type === "add"));
  block.length = 0;
}

function computeLines(oldText: string, newText: string, ignoreWs: boolean, maxLines: number) {
  let o = splitLines(oldText);
  let n = splitLines(newText);
  let truncated = false;
  if (o.length > maxLines || n.length > maxLines) {
    truncated = true;
    o = o.slice(0, maxLines);
    n = n.slice(0, maxLines);
  }
  const parts = diffLines(o.join("\n") + "\n", n.join("\n") + "\n", { ignoreWhitespace: ignoreWs });
  const out: DLine[] = [];
  const block: DLine[] = [];
  let oi = 1;
  let ni = 1;
  for (const p of parts) {
    const ls = splitLines(p.value);
    if (p.added) {
      for (const t of ls) block.push({ type: "add", newNo: ni++, text: t });
    } else if (p.removed) {
      for (const t of ls) block.push({ type: "del", oldNo: oi++, text: t });
    } else {
      flushBlock(out, block);
      for (const t of ls) out.push({ type: "ctx", oldNo: oi++, newNo: ni++, text: t });
    }
  }
  flushBlock(out, block);
  return { lines: out, truncated };
}

/** Parse a unified patch into hunks of lines. Headers (diff/index/---/+++) are skipped. */
function parsePatchText(patch: string, maxLines: number) {
  const items: { header?: string; line?: DLine }[] = [];
  let oi = 0;
  let ni = 0;
  let count = 0;
  let truncated = false;
  let inHunk = false;
  let block: DLine[] = [];
  const flushInto = () => {
    const tmp: DLine[] = [];
    flushBlock(tmp, block);
    tmp.forEach((line) => items.push({ line }));
  };
  for (const raw of patch.replace(/\r\n/g, "\n").split("\n")) {
    const h = raw.match(/^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@(.*)$/);
    if (h) {
      flushInto();
      oi = parseInt(h[1], 10);
      ni = parseInt(h[2], 10);
      items.push({ header: raw });
      inHunk = true;
      continue;
    }
    if (!inHunk) continue; // still in file header
    if (count >= maxLines * 2) { truncated = true; break; }
    const c = raw[0];
    const text = raw.slice(1);
    if (c === "+") block.push({ type: "add", newNo: ni++, text });
    else if (c === "-") block.push({ type: "del", oldNo: oi++, text });
    else if (c === " ") {
      flushInto();
      block = [];
      items.push({ line: { type: "ctx", oldNo: oi++, newNo: ni++, text } });
    } else continue; // "\ No newline at end of file" or trailing blank
    count++;
  }
  flushInto();
  return { items, truncated };
}

/** Fold long runs of unchanged lines. */
function buildItems(lines: DLine[], context: number): Item[] {
  const items: Item[] = [];
  const keep = new Array<boolean>(lines.length).fill(false);
  lines.forEach((l, i) => {
    if (l.type !== "ctx") {
      for (let k = Math.max(0, i - context); k <= Math.min(lines.length - 1, i + context); k++) keep[k] = true;
    }
  });
  let id = 0;
  let i = 0;
  while (i < lines.length) {
    if (keep[i]) {
      items.push({ kind: "line", line: lines[i++] });
      continue;
    }
    let j = i;
    while (j < lines.length && !keep[j]) j++;
    const run = lines.slice(i, j);
    // Folding fewer than 3 lines saves nothing.
    if (run.length < 3) run.forEach((line) => items.push({ kind: "line", line }));
    else items.push({ kind: "fold", id: id++, lines: run });
    i = j;
  }
  return items;
}

const rowBg: Record<LineType, string> = {
  ctx: "",
  add: "bg-emerald-500/10",
  del: "bg-destructive/15",
};
const segBg: Record<"add" | "del", string> = {
  add: "bg-emerald-500/30",
  del: "bg-destructive/40",
};

function LineText({ line }: { line: DLine }) {
  const kind = line.type === "ctx" ? null : line.type;
  let content: ReactNode = line.text === "" ? " " : line.text;
  if (line.segs && kind) {
    content = line.segs.map((s, i) => (
      <span key={i} className={s.changed ? cn("rounded-sm", segBg[kind]) : undefined}>
        {s.text}
      </span>
    ));
  }
  // dir="auto" per line so Persian lines render RTL while the grid stays LTR.
  return (
    <span dir="auto" className="min-w-0 whitespace-pre-wrap break-words [unicode-bidi:plaintext]">
      {content}
    </span>
  );
}

const SIGN: Record<LineType, string> = { ctx: " ", add: "+", del: "-" };
const numCls = "select-none px-2 text-end text-[10px] leading-5 text-muted-foreground/70 tabular-nums";

function UnifiedRow({ line }: { line: DLine }) {
  return (
    <div className={cn("grid grid-cols-[3rem_3rem_1.25rem_minmax(0,1fr)]", rowBg[line.type])}>
      <span className={numCls}>{line.oldNo ?? ""}</span>
      <span className={numCls}>{line.newNo ?? ""}</span>
      <span className="select-none text-center text-muted-foreground">{SIGN[line.type]}</span>
      <LineText line={line} />
    </div>
  );
}

function SplitCell({ line }: { line?: DLine }) {
  if (!line) return <div className="grid grid-cols-[3rem_minmax(0,1fr)] bg-muted/30"><span /><span /></div>;
  return (
    <div className={cn("grid grid-cols-[3rem_minmax(0,1fr)]", rowBg[line.type])}>
      <span className={numCls}>{line.type === "add" ? line.newNo : line.oldNo}</span>
      <LineText line={line} />
    </div>
  );
}

/** Pair consecutive del/add runs side by side for split mode. */
function toSplitRows(lines: DLine[]): { l?: DLine; r?: DLine }[] {
  const rows: { l?: DLine; r?: DLine }[] = [];
  let i = 0;
  while (i < lines.length) {
    const ln = lines[i];
    if (ln.type === "ctx") { rows.push({ l: ln, r: ln }); i++; continue; }
    const dels: DLine[] = [];
    const adds: DLine[] = [];
    while (i < lines.length && lines[i].type !== "ctx") {
      (lines[i].type === "del" ? dels : adds).push(lines[i]);
      i++;
    }
    for (let k = 0; k < Math.max(dels.length, adds.length); k++) rows.push({ l: dels[k], r: adds[k] });
  }
  return rows;
}

export function DiffViewer({
  oldText = "",
  newText = "",
  unifiedPatch,
  mode: modeProp,
  onModeChange,
  ignoreWhitespace = false,
  onIgnoreWhitespaceChange,
  oldLabel,
  newLabel,
  binary = false,
  contextLines = 3,
  maxLines = 5000,
  className,
}: DiffViewerProps) {
  const t = useSettingsStore((s) => s.t);
  // Uncontrolled fallback: the toolbar toggle works even without onModeChange.
  const [localMode, setLocalMode] = useState<DiffMode | null>(null);
  const mode = onModeChange ? modeProp : (localMode ?? modeProp);
  const [expanded, setExpanded] = useState<Set<number>>(() => new Set());

  const model = useMemo(() => {
    if (binary || (unifiedPatch && /^Binary files .* differ$/m.test(unifiedPatch))) {
      return { binary: true as const };
    }
    if (unifiedPatch !== undefined) {
      const { items, truncated } = parsePatchText(unifiedPatch, maxLines);
      const out: Item[] = [];
      let cur: DLine[] = [];
      let fid = 0;
      const flush = () => {
        if (cur.length) buildItems(cur, contextLines).forEach((it) => out.push(it.kind === "fold" ? { ...it, id: fid++ } : it));
        cur = [];
      };
      for (const it of items) {
        if (it.header !== undefined) { flush(); out.push({ kind: "hunk", header: it.header }); }
        else if (it.line) cur.push(it.line);
      }
      flush();
      return { binary: false as const, items: out, truncated, empty: !items.some((i) => i.line) };
    }
    const { lines, truncated } = computeLines(oldText, newText, ignoreWhitespace, maxLines);
    const items = buildItems(lines, contextLines);
    return { binary: false as const, items, truncated, empty: !lines.some((l) => l.type !== "ctx") };
  }, [oldText, newText, unifiedPatch, ignoreWhitespace, binary, contextLines, maxLines]);

  const stats = useMemo(() => {
    let add = 0;
    let del = 0;
    if (!model.binary) {
      const count = (l: DLine) => { if (l.type === "add") add++; else if (l.type === "del") del++; };
      model.items.forEach((it) => { if (it.kind === "line") count(it.line); });
    }
    return { add, del };
  }, [model]);

  const expand = (id: number) => setExpanded((s) => new Set(s).add(id));

  /** Expand folds into plain line items. */
  const flat = useMemo(() => {
    if (model.binary) return [];
    const out: Item[] = [];
    for (const it of model.items) {
      if (it.kind === "fold" && expanded.has(it.id)) it.lines.forEach((line) => out.push({ kind: "line", line }));
      else out.push(it);
    }
    return out;
  }, [model, expanded]);

  const renderFold = (it: Extract<Item, { kind: "fold" }>) => (
    <button
      key={`f${it.id}`}
      type="button"
      onClick={() => expand(it.id)}
      className="flex w-full items-center justify-center gap-1.5 bg-muted/40 py-0.5 text-[11px] text-muted-foreground hover:bg-accent hover:text-accent-foreground"
    >
      <ChevronsUpDown className="h-3 w-3" />
      {t("diffExpandLines").replace("{n}", String(it.lines.length))}
    </button>
  );

  const body = () => {
    if (model.binary) {
      return (
        <div className="flex h-full flex-col items-center justify-center gap-2 p-6 text-sm text-muted-foreground">
          <FileWarning className="h-8 w-8" />
          {t("diffBinary")}
        </div>
      );
    }
    if (model.empty) {
      return <div className="p-6 text-center text-sm text-muted-foreground">{t("diffNoChanges")}</div>;
    }
    if (mode === "unified") {
      return flat.map((it, i) =>
        it.kind === "line" ? <UnifiedRow key={i} line={it.line} /> :
        it.kind === "fold" ? renderFold(it) :
        <div key={i} className="bg-primary/10 px-3 py-0.5 text-[11px] text-muted-foreground">{it.header}</div>
      );
    }
    // Split: group consecutive line items so del/add runs can be paired.
    const nodes: ReactNode[] = [];
    let buf: DLine[] = [];
    const flushBuf = (k: string) => {
      toSplitRows(buf).forEach((r, i) =>
        nodes.push(
          <div key={`${k}-${i}`} className="grid grid-cols-2 divide-x divide-border">
            <SplitCell line={r.l} />
            <SplitCell line={r.r} />
          </div>
        )
      );
      buf = [];
    };
    flat.forEach((it, i) => {
      if (it.kind === "line") { buf.push(it.line); return; }
      flushBuf(`s${i}`);
      nodes.push(it.kind === "fold" ? renderFold(it) :
        <div key={`h${i}`} className="bg-primary/10 px-3 py-0.5 text-[11px] text-muted-foreground">{it.header}</div>);
    });
    flushBuf("end");
    return nodes;
  };

  return (
    <div className={cn("flex h-full min-h-0 flex-col overflow-hidden rounded-md border bg-card text-card-foreground", className)}>
      <div className="flex flex-wrap items-center gap-2 border-b bg-muted/40 px-3 py-1.5 text-xs">
        <div dir="auto" className="flex min-w-0 flex-1 items-center gap-2 truncate font-mono">
          <span className="truncate text-destructive-foreground/80" title={oldLabel}>{oldLabel}</span>
          <span className="text-muted-foreground">→</span>
          <span className="truncate" title={newLabel}>{newLabel}</span>
        </div>
        {!model.binary && (
          <span className="tabular-nums text-muted-foreground" dir="ltr">
            <span className="text-emerald-500">+{stats.add}</span>{" "}
            <span className="text-destructive">-{stats.del}</span>
          </span>
        )}
        {onIgnoreWhitespaceChange && unifiedPatch === undefined && (
          <label className="flex cursor-pointer items-center gap-1 text-muted-foreground">
            <input type="checkbox" checked={ignoreWhitespace} onChange={(e) => onIgnoreWhitespaceChange(e.target.checked)} />
            {t("diffIgnoreWs")}
          </label>
        )}
        <div role="group" className="flex overflow-hidden rounded-md border">
          {(["split", "unified"] as const).map((m) => (
            <button
              key={m}
              type="button"
              aria-pressed={mode === m}
              onClick={() => { setLocalMode(m); onModeChange?.(m); }}
              className={cn(
                "flex items-center gap-1 px-2 py-1 transition-colors",
                mode === m ? "bg-primary text-primary-foreground" : "hover:bg-accent"
              )}
            >
              {m === "split" ? <Columns2 className="h-3.5 w-3.5" /> : <Rows2 className="h-3.5 w-3.5" />}
              {t(m === "split" ? "diffSplit" : "diffUnified")}
            </button>
          ))}
        </div>
      </div>
      {!model.binary && model.truncated && (
        <div role="status" className="border-b bg-amber-500/10 px-3 py-1 text-[11px] text-amber-500">{t("diffTooLarge")}</div>
      )}
      <div
        dir="ltr"
        className="min-h-0 flex-1 select-text overflow-auto font-mono text-xs leading-5"
        style={{ fontFamily: '"Cascadia Mono", Consolas, "Vazirmatn", monospace' }}
      >
        {body()}
      </div>
    </div>
  );
}

export default DiffViewer;
