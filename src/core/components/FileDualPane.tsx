import { forwardRef, useImperativeHandle, useRef, type ReactNode } from "react";
import { PathBar } from "@/core/components/PathBar";
import {
  VirtualFileList,
  type FileEntry,
  type FileDropInfo,
  type VirtualFileListProps,
} from "@/core/components/VirtualFileList";
import { cn } from "@/core/utils/cn";

export type PaneSide = "left" | "right";

/** Per-pane configuration. `dragType`, `id` and drop handlers are supplied by FileDualPane. */
export interface FilePaneConfig
  extends Omit<VirtualFileListProps, "dragType" | "id" | "path" | "onDropEntries" | "onDropFiles" | "className"> {
  path: string;
  onNavigate: (path: string) => void;
  /** Slot rendered between the path bar and the list (toolbar, drive picker, host selector...). */
  header?: ReactNode;
  /** Slot rendered under the list. */
  footer?: ReactNode;
}

export interface TransferInfo {
  from: PaneSide;
  entries: FileEntry[];
  targetPath: string;
}

export interface ExternalDropInfo {
  side: PaneSide;
  targetPath: string;
  /** Browser File objects (empty when injected from a native/Tauri drop event). */
  files: File[];
  /** Absolute paths when known (Tauri drop event injection). */
  paths: string[];
}

export interface FileDualPaneProps {
  left: FilePaneConfig;
  right: FilePaneConfig;
  onTransfer: (info: TransferInfo) => void;
  onExternalDrop?: (info: ExternalDropInfo) => void;
  /** Currently focused pane (highlight only). */
  activePane?: PaneSide;
  onActivePaneChange?: (side: PaneSide) => void;
  /** Drag payload key shared by both lists. Default "application/x-nora-files". */
  dragType?: string;
  className?: string;
}

export interface FileDualPaneHandle {
  /** Inject OS paths for a pane (use with Tauri's webview drag-drop event). */
  injectExternalDrop: (side: PaneSide, paths: string[]) => void;
  /** Same, but resolves the pane from window coordinates (CSS px). Returns the side hit, or null. */
  injectExternalDropAt: (point: { x: number; y: number }, paths: string[]) => PaneSide | null;
}

export const FileDualPane = forwardRef<FileDualPaneHandle, FileDualPaneProps>(function FileDualPane(
  { left, right, onTransfer, onExternalDrop, activePane, onActivePaneChange, dragType = "application/x-nora-files", className },
  ref
) {
  const leftEl = useRef<HTMLDivElement>(null);
  const rightEl = useRef<HTMLDivElement>(null);

  const emitExternal = (side: PaneSide, files: File[], paths: string[], target?: string) => {
    const cfg = side === "left" ? left : right;
    onExternalDrop?.({ side, targetPath: target ?? cfg.path, files, paths });
  };

  useImperativeHandle(ref, () => ({
    injectExternalDrop: (side, paths) => emitExternal(side, [], paths),
    injectExternalDropAt: ({ x, y }, paths) => {
      const hit = (el: HTMLDivElement | null) => {
        const r = el?.getBoundingClientRect();
        return !!r && x >= r.left && x <= r.right && y >= r.top && y <= r.bottom;
      };
      const side: PaneSide | null = hit(leftEl.current) ? "left" : hit(rightEl.current) ? "right" : null;
      if (side) emitExternal(side, [], paths);
      return side;
    },
  }));

  const renderPane = (side: PaneSide, cfg: FilePaneConfig, elRef: typeof leftEl) => {
    const { path, onNavigate, header, footer, ...listProps } = cfg;
    const onDropEntries = (info: FileDropInfo) =>
      onTransfer({ from: info.sourceId === "right" ? "right" : "left", entries: info.entries, targetPath: info.targetPath });
    return (
      <div
        ref={elRef}
        onFocusCapture={() => onActivePaneChange?.(side)}
        onMouseDownCapture={() => onActivePaneChange?.(side)}
        className={cn(
          "flex min-h-0 min-w-0 flex-1 flex-col gap-2 rounded-lg border p-2 transition-colors",
          activePane === side ? "border-primary/60" : "border-transparent"
        )}
      >
        <PathBar path={path} onNavigate={onNavigate} />
        {header}
        <div className="min-h-0 flex-1">
          <VirtualFileList
            {...listProps}
            id={side}
            path={path}
            dragType={dragType}
            onDropEntries={onDropEntries}
            onDropFiles={(files, target) => emitExternal(side, files, [], target)}
          />
        </div>
        {footer}
      </div>
    );
  };

  return (
    // dir="ltr" pins left=source / right=target visually; each list restores the page direction itself.
    <div dir="ltr" className={cn("flex h-full min-h-0 w-full gap-2", className)}>
      {renderPane("left", left, leftEl)}
      {renderPane("right", right, rightEl)}
    </div>
  );
});

export default FileDualPane;
