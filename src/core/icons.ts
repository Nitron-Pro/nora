import {
  LayoutDashboard, Cpu, ListTodo, Settings, Radio, Printer, CheckCircle2, Clock, Archive,
  Server, Package, Rocket, FolderOpen, SquareTerminal, History,
  type LucideIcon,
} from "lucide-react";

/**
 * Sidebar icon registry. Menu items in `src/app/config.ts` refer to icons by name.
 * Child apps add icons WITHOUT touching core:
 *   - create `src/app/icons.ts` (auto-loaded) exporting `export const APP_ICONS = { Rocket, ... }`, or
 *   - call `registerIcons({ Name: LucideComponent })` anywhere before first render.
 * Unknown names fall back to LayoutDashboard.
 */
const registry: Record<string, LucideIcon> = {
  LayoutDashboard, Cpu, ListTodo, Settings, Radio, Printer, CheckCircle2, Clock, Archive,
  Server, Package, Rocket, FolderOpen, SquareTerminal, History,
};

export function registerIcons(icons: Record<string, LucideIcon>): void {
  Object.assign(registry, icons);
}

// Optional per-app icon module: src/app/icons.ts (export const APP_ICONS = {...}).
const appIconModules = import.meta.glob<{ APP_ICONS?: Record<string, LucideIcon> }>(
  "/src/app/icons.ts",
  { eager: true },
);
for (const mod of Object.values(appIconModules)) {
  if (mod.APP_ICONS) registerIcons(mod.APP_ICONS);
}

export function getIcon(name?: string): LucideIcon | null {
  return name ? registry[name] ?? null : null;
}
