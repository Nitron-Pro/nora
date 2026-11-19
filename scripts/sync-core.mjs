/**
 * Nora - unified core sync for child apps (replaces the manual `git checkout core/main -- ...` line).
 *
 *   node scripts/sync-core.mjs                 # fetch `core` remote and apply core/main
 *   node scripts/sync-core.mjs --dry-run       # show what would change
 *   node scripts/sync-core.mjs --remote core --ref main
 *
 * What it does (safe: never touches src/app/, never git-merges):
 *  1. git fetch <remote>
 *  2. reads core-manifest.json FROM THE NEW CORE and checks out exactly those paths
 *  3. deletes local files under core paths that no longer exist in core (removed upstream)
 *  4. merges package.json (core scripts + core dependency ranges; child-only deps are kept)
 *  5. merges src-tauri/Cargo.toml (child [package] kept; block after '# --- child-app deps ---' kept)
 *  6. prints the old -> new core version
 */
import { execFileSync } from "child_process";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
process.chdir(root);
const args = process.argv.slice(2);
const opt = (name, def) => { const i = args.indexOf(`--${name}`); return i >= 0 ? args[i + 1] : def; };
const dry = args.includes("--dry-run");
const remote = opt("remote", "core");
const ref = `${remote}/${opt("ref", "main")}`;

const git = (...a) => execFileSync("git", a, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
const gitShow = (p) => { try { return git("show", `${ref}:${p}`); } catch { return null; } };

const oldVersion = (() => {
  try { return /CORE_VERSION\s*=\s*"([^"]+)"/.exec(fs.readFileSync("src/core/version.ts", "utf8"))[1]; } catch { return "unknown"; }
})();

console.log(`[sync-core] fetching '${remote}' ...`);
git("fetch", remote);

const manifestRaw = gitShow("core-manifest.json");
if (!manifestRaw) throw new Error(`core-manifest.json not found in ${ref}. Is the mother repo >= 1.8.0?`);
const manifest = JSON.parse(manifestRaw);
if (manifest.paths.some((p) => p.split("\\").join("/").startsWith("src/app"))) throw new Error("manifest lists src/app - refusing.");

// Only paths that exist in the ref
const existing = manifest.paths.filter((p) => { try { git("cat-file", "-e", `${ref}:${p}`); return true; } catch { return false; } });

// Removed-upstream files under core paths
const removed = [];
for (const p of existing) {
  const upstream = new Set(git("ls-tree", "-r", "--name-only", ref, "--", p).split("\n").filter(Boolean));
  let local = [];
  try { local = git("ls-files", "--", p).split("\n").filter(Boolean); } catch { /* none */ }
  for (const f of local) if (!upstream.has(f)) removed.push(f);
}

console.log(`[sync-core] ${oldVersion} -> ${manifest.coreVersion}`);
console.log(`[sync-core] checkout: ${existing.join(", ")}`);
if (removed.length) console.log(`[sync-core] remove: ${removed.join(", ")}`);
if (dry) { console.log("[sync-core] dry-run: nothing changed."); process.exit(0); }

// Keep child-owned Cargo.toml / package.json to merge afterwards
const childCargo = fs.existsSync("src-tauri/Cargo.toml") ? fs.readFileSync("src-tauri/Cargo.toml", "utf8") : null;
const childPkg = fs.existsSync("package.json") ? JSON.parse(fs.readFileSync("package.json", "utf8")) : null;

git("checkout", ref, "--", ...existing);
for (const f of removed) { try { git("rm", "-q", "-f", "--", f); } catch { fs.rmSync(f, { force: true }); } }

// package.json merge
const corePkg = JSON.parse(gitShow("package.json") || "{}");
if (childPkg && corePkg.name !== undefined) {
  const merged = { ...childPkg };
  merged.scripts = { ...(childPkg.scripts || {}), ...(corePkg.scripts || {}) };
  for (const key of ["dependencies", "devDependencies"]) {
    merged[key] = { ...(childPkg[key] || {}), ...(corePkg[key] || {}) };
  }
  fs.writeFileSync("package.json", JSON.stringify(merged, null, 2) + "\n");
}

// Cargo.toml merge: child [package] + child deps block preserved
if (childCargo) {
  const coreCargo = fs.readFileSync("src-tauri/Cargo.toml", "utf8");
  const pkgRe = /\[package\][\s\S]*?(?=\n\[)/;
  const childPkgSec = childCargo.match(pkgRe)?.[0];
  let out = childPkgSec ? coreCargo.replace(pkgRe, childPkgSec) : coreCargo;
  const marker = "# --- child-app deps ---";
  const idx = childCargo.indexOf(marker);
  if (idx >= 0) {
    const block = childCargo.slice(idx).split(/\n\[/)[0];
    out = out.includes(marker) ? out : out.replace(/\n\[dependencies\]\n/, `\n[dependencies]\n${block}\n`);
  }
  fs.writeFileSync("src-tauri/Cargo.toml", out);
}

console.log(`[sync-core] done. Now run: npm install && npm run build && (cd src-tauri && cargo check)`);
console.log(`[sync-core] then commit: git add -A && git commit -m "chore: sync core ${manifest.coreVersion}"`);
