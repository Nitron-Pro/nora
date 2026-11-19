import { forwardRef, useEffect, useImperativeHandle, useRef } from "react";
import { Terminal as XTerm, type ITheme } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { cn } from "@/core/utils/cn";

export interface TerminalHandle {
  write: (data: string | Uint8Array) => void;
  clear: () => void;
  focus: () => void;
  fit: () => void;
}

export interface TerminalProps {
  /** User keystrokes / pasted data to forward to the PTY. */
  onData?: (data: string) => void;
  /** Fired when the grid size changes (after fit). */
  onResize?: (size: { cols: number; rows: number }) => void;
  readOnly?: boolean;
  fontSize?: number;
  className?: string;
  ariaLabel?: string;
}

/** Read an `H S% L%` CSS variable and convert it to a #rrggbb string. */
function cssVarToHex(name: string, fallback: string): string {
  const raw = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const m = raw.match(/^(-?[\d.]+)[\s,]+([\d.]+)%[\s,]+([\d.]+)%/);
  if (!m) return fallback;
  const h = ((parseFloat(m[1]) % 360) + 360) % 360;
  const s = parseFloat(m[2]) / 100;
  const l = parseFloat(m[3]) / 100;
  const a = s * Math.min(l, 1 - l);
  const f = (n: number) => {
    const k = (n + h / 30) % 12;
    const c = l - a * Math.max(-1, Math.min(k - 3, Math.min(9 - k, 1)));
    return Math.round(c * 255).toString(16).padStart(2, "0");
  };
  return `#${f(0)}${f(8)}${f(4)}`;
}

// ANSI palettes are semantic (red/green/...) and cannot be derived from UI tokens.
const ANSI_DARK = {
  black: "#1e293b", red: "#f87171", green: "#4ade80", yellow: "#facc15",
  blue: "#60a5fa", magenta: "#c084fc", cyan: "#22d3ee", white: "#e2e8f0",
  brightBlack: "#64748b", brightRed: "#fca5a5", brightGreen: "#86efac", brightYellow: "#fde047",
  brightBlue: "#93c5fd", brightMagenta: "#d8b4fe", brightCyan: "#67e8f9", brightWhite: "#f8fafc",
};
const ANSI_LIGHT = {
  black: "#27272a", red: "#b91c1c", green: "#15803d", yellow: "#a16207",
  blue: "#1d4ed8", magenta: "#7e22ce", cyan: "#0e7490", white: "#d4d4d8",
  brightBlack: "#52525b", brightRed: "#dc2626", brightGreen: "#16a34a", brightYellow: "#ca8a04",
  brightBlue: "#2563eb", brightMagenta: "#9333ea", brightCyan: "#0891b2", brightWhite: "#fafafa",
};

function buildTheme(): ITheme {
  const isLight = document.documentElement.classList.contains("light");
  const bg = cssVarToHex("--background", isLight ? "#ffffff" : "#0b1120");
  const fg = cssVarToHex("--foreground", isLight ? "#09090b" : "#f8fafc");
  const sel = cssVarToHex("--accent", isLight ? "#f4f4f5" : "#1e293b");
  return {
    ...(isLight ? ANSI_LIGHT : ANSI_DARK),
    background: bg,
    foreground: fg,
    cursor: cssVarToHex("--primary", fg),
    cursorAccent: bg,
    selectionBackground: sel,
    selectionInactiveBackground: sel,
  };
}

const FONT_FAMILY =
  '"Cascadia Mono", "Cascadia Code", Consolas, "Vazirmatn", "Courier New", monospace';

export const Terminal = forwardRef<TerminalHandle, TerminalProps>(function Terminal(
  { onData, onResize, readOnly = false, fontSize = 13, className, ariaLabel },
  ref
) {
  const hostRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<XTerm | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const cbRef = useRef({ onData, onResize, readOnly });
  cbRef.current = { onData, onResize, readOnly };

  const doFit = () => {
    const host = hostRef.current;
    // Skip while hidden / zero-sized to avoid a 0x0 grid.
    if (!host || host.clientWidth < 8 || host.clientHeight < 8) return;
    try {
      fitRef.current?.fit();
    } catch {
      /* terminal disposed or not yet rendered */
    }
  };

  useImperativeHandle(ref, () => ({
    write: (data) => termRef.current?.write(data),
    clear: () => termRef.current?.clear(),
    focus: () => termRef.current?.focus(),
    fit: doFit,
  }));

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    const term = new XTerm({
      fontFamily: FONT_FAMILY,
      fontSize,
      cursorBlink: true,
      allowProposedApi: false,
      scrollback: 5000,
      theme: buildTheme(),
      disableStdin: cbRef.current.readOnly,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(host);
    termRef.current = term;
    fitRef.current = fit;

    const dataSub = term.onData((d) => {
      if (!cbRef.current.readOnly) cbRef.current.onData?.(d);
    });
    const resizeSub = term.onResize(({ cols, rows }) => cbRef.current.onResize?.({ cols, rows }));

    let raf = 0;
    const schedule = () => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(doFit);
    };
    const ro = new ResizeObserver(schedule);
    ro.observe(host);
    schedule();

    // Re-theme when the app theme class changes on <html>.
    const mo = new MutationObserver(() => {
      term.options.theme = buildTheme();
    });
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      mo.disconnect();
      dataSub.dispose();
      resizeSub.dispose();
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const term = termRef.current;
    if (!term) return;
    term.options.fontSize = fontSize;
    doFit();
  }, [fontSize]);

  useEffect(() => {
    if (termRef.current) termRef.current.options.disableStdin = readOnly;
  }, [readOnly]);

  return (
    // dir="ltr" keeps the terminal grid from being mirrored by an RTL page.
    <div
      dir="ltr"
      role="group"
      aria-label={ariaLabel ?? "Terminal"}
      className={cn("h-full w-full overflow-hidden bg-background p-2 text-left", className)}
    >
      <div ref={hostRef} className="h-full w-full" />
    </div>
  );
});

export default Terminal;
