import { open } from "@tauri-apps/plugin-dialog";

export interface FileFilter {
  /** Display name, e.g. "Archives" */
  name: string;
  /** Extensions without dot, e.g. ["zip", "tar"] */
  extensions: string[];
}

/** Native Windows pickers (folder / files). Paths are absolute and always use "/" separators. */
const norm = (p: string) => p.split("\\").join("/");

export const DialogService = {
  /** Pick a folder. Resolves to null when the user cancels. */
  async pickFolder(opts: { title?: string; defaultPath?: string } = {}): Promise<string | null> {
    const res = await open({ directory: true, multiple: false, title: opts.title, defaultPath: opts.defaultPath });
    return typeof res === "string" ? norm(res) : null;
  },

  /** Pick one or more files. Resolves to [] when the user cancels. */
  async pickFiles(
    opts: { multiple?: boolean; filters?: FileFilter[]; title?: string; defaultPath?: string } = {},
  ): Promise<string[]> {
    const res = await open({
      directory: false,
      multiple: opts.multiple ?? false,
      title: opts.title,
      defaultPath: opts.defaultPath,
      filters: opts.filters,
    });
    if (res == null) return [];
    return (Array.isArray(res) ? res : [res]).map(norm);
  },
};
