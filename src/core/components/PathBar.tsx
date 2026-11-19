import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { ChevronRight, ChevronLeft } from "lucide-react";
import { useSettingsStore } from "@/core/store/settingsStore";
import { cn } from "@/core/utils/cn";

export interface PathBarProps {
  path: string;
  onNavigate: (path: string) => void;
  /** Allow click-to-edit text mode. Default true. */
  editable?: boolean;
  className?: string;
}

interface Crumb { label: string; path: string }

/** Split a Windows or POSIX style path into clickable crumbs. */
export function pathToCrumbs(path: string): Crumb[] {
  if (!path) return [];
  const sep = path.includes("\\") && !path.startsWith("/") ? "\\" : "/";
  const parts = path.split(sep).filter((p, i) => p !== "" || i === 0);
  const crumbs: Crumb[] = [];
  let acc = "";
  parts.forEach((p, i) => {
    if (i === 0 && p === "") {
      acc = sep;
      crumbs.push({ label: sep, path: sep });
      return;
    }
    if (i === 0 && sep === "\\" && /^[A-Za-z]:$/.test(p)) {
      acc = p + sep; // drive root keeps its trailing separator
      crumbs.push({ label: p, path: acc });
      return;
    }
    acc = acc === "" ? p : acc.endsWith(sep) ? acc + p : acc + sep + p;
    crumbs.push({ label: p, path: acc });
  });
  return crumbs;
}

export function PathBar({ path, onNavigate, editable = true, className }: PathBarProps) {
  const t = useSettingsStore((s) => s.t);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(path);
  const inputRef = useRef<HTMLInputElement>(null);
  const crumbs = useMemo(() => pathToCrumbs(path), [path]);
  const Sep = document.documentElement.dir === "rtl" ? ChevronLeft : ChevronRight;

  useEffect(() => { if (!editing) setDraft(path); }, [path, editing]);
  useEffect(() => { if (editing) inputRef.current?.select(); }, [editing]);

  const commit = () => {
    setEditing(false);
    if (draft.trim() && draft !== path) onNavigate(draft.trim());
  };
  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") commit();
    else if (e.key === "Escape") { setEditing(false); setDraft(path); }
  };

  return (
    // Paths are always LTR text, even inside an RTL page.
    <div
      dir="ltr"
      role="navigation"
      aria-label={t("filePathBar")}
      className={cn("flex h-8 min-w-0 items-center rounded-md border bg-background px-1 text-xs", className)}
    >
      {editing ? (
        <input
          ref={inputRef}
          autoFocus
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onBlur={commit}
          onKeyDown={onKey}
          spellCheck={false}
          className="h-full min-w-0 flex-1 bg-transparent px-1 font-mono outline-none"
        />
      ) : (
        <div
          className="flex min-w-0 flex-1 items-center overflow-x-auto whitespace-nowrap"
          onDoubleClick={() => editable && setEditing(true)}
          onClick={(e) => { if (editable && e.target === e.currentTarget) setEditing(true); }}
        >
          {crumbs.map((c, i) => (
            <span key={c.path + i} className="flex items-center">
              {i > 0 && c.label !== "" && crumbs[i - 1].label !== "/" && crumbs[i - 1].label !== "\\" && (
                <Sep className="h-3 w-3 shrink-0 text-muted-foreground" />
              )}
              <button
                type="button"
                onClick={() => onNavigate(c.path)}
                className="rounded px-1.5 py-0.5 hover:bg-accent hover:text-accent-foreground"
              >
                {c.label}
              </button>
            </span>
          ))}
          <span
            className="h-full min-w-4 flex-1 cursor-text"
            onClick={() => editable && setEditing(true)}
          />
        </div>
      )}
    </div>
  );
}

export default PathBar;
