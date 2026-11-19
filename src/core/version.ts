/**
 * Nora core engine version (independent of the child app's own `APP_CONFIG.version`).
 * Bumped on every core change; travels to child apps with `src/core` via scripts/sync-core.mjs.
 */
export const CORE_VERSION = "1.8.1";
