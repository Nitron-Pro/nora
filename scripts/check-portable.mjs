/**
 * Nora Core - Portable-First guard (Zero C-Drive Pollution).
 * Fails when Rust/TS source uses Windows-drive storage locations.
 * Run automatically before build (see package.json "prebuild"/"predev") and in CI.
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const scanDirs = ["src-tauri/src", "src"];
const exts = new Set([".rs", ".ts", ".tsx"]);
// Words only allowed inside comments/docs are still flagged on purpose except in this allow-list.
const allowFiles = new Set(["src-tauri/src/portable.rs"]);
const rules = [
  [/(app_local_data_dir|app_data_dir|app_config_dir|app_cache_dir|app_log_dir)\s*\(/, "Tauri app_*_dir resolves to C:\Users\...\AppData"],
  [/temp_dir\s*\(/, "temp_dir() writes to %TEMP% on the Windows drive"],
  [/\bdirs::|\bdirs_next::|\bdirectories::|ProjectDirs|BaseDirectory::/, "OS-standard directories crate/API"],
  [/%APPDATA%|%LOCALAPPDATA%|%TEMP%|%USERPROFILE%|%HOMEPATH%/i, "hard-coded Windows environment path"],
  [/["'`]\s*[Cc]:[\/]/, "hard-coded C: drive path"],
  [/env::var(_os)?\(\s*"(APPDATA|LOCALAPPDATA|TEMP|TMP|USERPROFILE|HOME)"/, "reads a Windows user-profile environment variable"],
  [/\bhome_dir\s*\(|\bdesktop_dir\s*\(|\bdocument_dir\s*\(|\bdownload_dir\s*\(/, "OS user-folder API"],
];

const problems = [];
function walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (["node_modules", "target", "dist", "gen"].includes(e.name)) continue;
      walk(p);
    } else if (exts.has(path.extname(e.name))) {
      const rel = path.relative(root, p).split(path.sep).join("/");
      if (allowFiles.has(rel)) continue;
      fs.readFileSync(p, "utf8").split(/\r?\n/).forEach((line, i) => {
        if (/portable-allow/.test(line)) return;
        if (/^\s*(\/\/|\*|\/\*)/.test(line)) return; // comments // explicit, reviewed exception
        for (const [re, why] of rules) {
          if (re.test(line)) problems.push(`${rel}:${i + 1}  ${why}\n    ${line.trim()}`);
        }
      });
    }
  }
}
for (const d of scanDirs) if (fs.existsSync(path.join(root, d))) walk(path.join(root, d));

if (problems.length) {
  console.error("[check-portable] Windows-drive storage usage found:\n" + problems.join("\n"));
  console.error("\nUse crate::portable::data_dir()/data_subdir() (nora-data next to the exe). See docs/PORTABLE_STORAGE.md.");
  process.exit(1);
}
console.log("[check-portable] OK - no Windows-drive storage usage.");
