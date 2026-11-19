//! Encrypted vault (Argon2id + XChaCha20-Poly1305), stored ONLY in `<exe_dir>/nora-data/vault/`.
//!
//! * The frontend can never read a secret value: there is no get-secret IPC. Rust code that needs a
//!   secret (SSH/SFTP/FTP connections) calls [`resolve_secret`].
//! * The master key and decrypted data live only in memory while unlocked and are zeroized on lock.
//! * State is a process-wide singleton; [`VaultState`] / [`init_state`] exist so `lib.rs` can
//!   `.manage(vault::init_state())` (optional: IPC commands do not require managed state).
//!
//! Error strings (stable, matched by the UI): `vault locked`, `vault not found`,
//! `vault already exists`, `wrong password`, `vault file corrupted`,
//! `too many attempts; retry in <N>s`, `secret not found`, `backup password required`,
//! otherwise a free-form message.

mod format;

use format::{Entry, Key, KeyCtx, OpenError, VaultData};
use serde::Serialize;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const DEFAULT_AUTO_LOCK_SECS: u64 = 900;
const VAULT_FILE: &str = "vault.nvlt";
const CFG_FILE: &str = "vault.cfg";
const MIN_PASSWORD_CHARS: usize = 8;
const MAX_SECRET_BYTES: usize = 64 * 1024;

/// Marker type to register with Tauri: `.manage(crate::vault::init_state())`.
/// All data lives in the process-wide singleton, so this is a zero-size handle.
#[derive(Default)]
pub struct VaultState;

pub fn init_state() -> VaultState {
    // Touch the singleton so the auto-lock timer starts early; ignore failures (reported on use).
    let _ = global();
    VaultState
}

#[derive(Serialize, Clone, Debug)]
pub struct VaultStatus {
    pub exists: bool,
    pub unlocked: bool,
    pub auto_lock_secs: u64,
}

#[derive(Serialize, Clone, Debug)]
pub struct SecretInfo {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub updated_at: i64,
}

struct Inner {
    key: Option<Key>,
    ctx: Option<KeyCtx>,
    data: Option<VaultData>,
    last_used: Option<Instant>,
    auto_lock_secs: u64,
    fails: u32,
    blocked_until: Option<Instant>,
}

impl Inner {
    fn lock_now(&mut self) {
        // Dropping the Zeroizing key and the Entries (Drop zeroizes secrets) wipes memory.
        self.key = None;
        self.ctx = None;
        self.data = None;
        self.last_used = None;
    }
}

pub struct Vault {
    dir: PathBuf,
    inner: Mutex<Inner>,
}

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Write `bytes` to `path` atomically: temp file in the SAME folder, fsync, then rename.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut tmp_name = path.file_name().ok_or("invalid path")?.to_os_string();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);
    let res = (|| -> std::io::Result<()> {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)
    })();
    if let Err(e) = res {
        let _ = fs::remove_file(&tmp);
        return Err(format!("write failed: {e}"));
    }
    Ok(())
}

fn check_password(p: &str) -> Result<(), String> {
    if p.chars().count() < MIN_PASSWORD_CHARS {
        return Err(format!("master password too short (min {MIN_PASSWORD_CHARS})"));
    }
    Ok(())
}

fn open_err(e: OpenError) -> String {
    match e {
        OpenError::Corrupt => "vault file corrupted".into(),
        OpenError::WrongPassword => "wrong password".into(),
    }
}

impl Vault {
    pub fn new(dir: PathBuf) -> Self {
        let auto = fs::read_to_string(dir.join(CFG_FILE))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_AUTO_LOCK_SECS);
        Vault {
            dir,
            inner: Mutex::new(Inner {
                key: None,
                ctx: None,
                data: None,
                last_used: None,
                auto_lock_secs: auto,
                fails: 0,
                blocked_until: None,
            }),
        }
    }

    fn path(&self) -> PathBuf {
        self.dir.join(VAULT_FILE)
    }

    fn g(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Run `f` on the unlocked state and reset the inactivity timer.
    fn with_unlocked<T>(&self, f: impl FnOnce(&mut Inner) -> Result<T, String>) -> Result<T, String> {
        let mut g = self.g();
        if g.key.is_none() || g.data.is_none() {
            return Err("vault locked".into());
        }
        g.last_used = Some(Instant::now());
        f(&mut g)
    }

    fn persist(&self, g: &Inner) -> Result<(), String> {
        let (key, ctx, data) = match (&g.key, &g.ctx, &g.data) {
            (Some(k), Some(c), Some(d)) => (k, c, d),
            _ => return Err("vault locked".into()),
        };
        let bytes = format::encrypt(data, key, ctx)?; // fresh random nonce each write
        atomic_write(&self.path(), &bytes)
    }

    /// Back-off after repeated wrong passwords: from the 3rd failure wait 1s, 2s, 4s ... max 5 min.
    fn check_rate_limit(&self) -> Result<(), String> {
        let g = self.g();
        if let Some(t) = g.blocked_until {
            let now = Instant::now();
            if t > now {
                let secs = (t - now).as_secs() + 1;
                return Err(format!("too many attempts; retry in {secs}s"));
            }
        }
        Ok(())
    }

    fn record_failure(&self) {
        let mut g = self.g();
        g.fails = g.fails.saturating_add(1);
        if g.fails >= 3 {
            let secs = (1u64 << (g.fails - 3).min(9)).min(300);
            g.blocked_until = Some(Instant::now() + Duration::from_secs(secs));
        }
    }

    fn record_success(&self) {
        let mut g = self.g();
        g.fails = 0;
        g.blocked_until = None;
    }

    pub fn status(&self) -> VaultStatus {
        let g = self.g();
        VaultStatus { exists: self.path().is_file(), unlocked: g.key.is_some(), auto_lock_secs: g.auto_lock_secs }
    }

    pub fn is_unlocked(&self) -> bool {
        self.g().key.is_some()
    }

    pub fn create(&self, password: &str) -> Result<(), String> {
        check_password(password)?;
        if self.path().exists() {
            return Err("vault already exists".into());
        }
        let ctx = format::new_ctx();
        let key = format::derive_key(password, &ctx)?;
        let data = VaultData::default();
        let bytes = format::encrypt(&data, &key, &ctx)?;
        atomic_write(&self.path(), &bytes)?;
        let mut g = self.g();
        g.key = Some(key);
        g.ctx = Some(ctx);
        g.data = Some(data);
        g.last_used = Some(Instant::now());
        Ok(())
    }

    pub fn unlock(&self, password: &str) -> Result<(), String> {
        self.check_rate_limit()?;
        let file = fs::read(self.path()).map_err(|_| "vault not found".to_string())?;
        let ctx = format::parse_ctx(&file).map_err(open_err)?;
        let key = format::derive_key(password, &ctx)?;
        match format::decrypt(&file, &key) {
            Ok(data) => {
                self.record_success();
                let mut g = self.g();
                g.key = Some(key);
                g.ctx = Some(ctx);
                g.data = Some(data);
                g.last_used = Some(Instant::now());
                Ok(())
            }
            Err(e) => {
                if matches!(e, OpenError::WrongPassword) {
                    self.record_failure();
                }
                Err(open_err(e))
            }
        }
    }

    pub fn lock(&self) {
        self.g().lock_now();
    }

    /// Called periodically by the background timer; locks after inactivity.
    pub fn tick(&self) {
        let mut g = self.g();
        if g.key.is_some() && g.auto_lock_secs > 0 {
            if let Some(t) = g.last_used {
                if t.elapsed() >= Duration::from_secs(g.auto_lock_secs) {
                    g.lock_now();
                }
            }
        }
    }

    pub fn set(&self, id: &str, secret: &str, label: Option<&str>, kind: Option<&str>) -> Result<(), String> {
        if id.is_empty() || id.len() > 256 || id.chars().any(|c| c.is_control()) {
            return Err("invalid secret id".into());
        }
        if secret.len() > MAX_SECRET_BYTES {
            return Err("secret too large".into());
        }
        self.with_unlocked(|g| {
            let data = g.data.as_mut().unwrap();
            let prev_kind = data.entries.get(id).map(|e| (e.label.clone(), e.kind.clone()));
            let label = label.map(|s| s.chars().take(256).collect::<String>())
                .or(prev_kind.as_ref().map(|p| p.0.clone())).unwrap_or_default();
            let kind = kind.map(|s| s.chars().take(32).collect::<String>())
                .or(prev_kind.map(|p| p.1)).unwrap_or_else(|| "password".into());
            let old = data.entries.insert(
                id.to_string(),
                Entry { secret: secret.to_string(), label, kind, updated_at: now_secs() },
            );
            if let Err(e) = self.persist(g) {
                // Roll back so memory and disk stay consistent.
                let data = g.data.as_mut().unwrap();
                match old {
                    Some(o) => { data.entries.insert(id.to_string(), o); }
                    None => { data.entries.remove(id); }
                }
                return Err(e);
            }
            Ok(())
        })
    }

    pub fn delete(&self, id: &str) -> Result<(), String> {
        self.with_unlocked(|g| {
            let old = g.data.as_mut().unwrap().entries.remove(id).ok_or("secret not found")?;
            if let Err(e) = self.persist(g) {
                g.data.as_mut().unwrap().entries.insert(id.to_string(), old);
                return Err(e);
            }
            Ok(())
        })
    }

    pub fn list(&self) -> Result<Vec<SecretInfo>, String> {
        self.with_unlocked(|g| {
            Ok(g.data.as_ref().unwrap().entries.iter().map(|(id, e)| SecretInfo {
                id: id.clone(), label: e.label.clone(), kind: e.kind.clone(), updated_at: e.updated_at,
            }).collect())
        })
    }

    pub fn has(&self, id: &str) -> Result<bool, String> {
        self.with_unlocked(|g| Ok(g.data.as_ref().unwrap().entries.contains_key(id)))
    }

    pub fn resolve(&self, id: &str) -> Result<Zeroizing<String>, String> {
        self.with_unlocked(|g| {
            g.data.as_ref().unwrap().entries.get(id)
                .map(|e| Zeroizing::new(e.secret.clone()))
                .ok_or_else(|| "secret not found".to_string())
        })
    }

    pub fn change_master(&self, old: &str, new: &str) -> Result<(), String> {
        check_password(new)?;
        self.check_rate_limit()?;
        // Verify the old password against the on-disk header (KDF runs without holding the lock).
        let file = fs::read(self.path()).map_err(|_| "vault not found".to_string())?;
        let ctx = format::parse_ctx(&file).map_err(open_err)?;
        let okey = format::derive_key(old, &ctx)?;
        if let Err(e) = format::decrypt(&file, &okey) {
            if matches!(e, OpenError::WrongPassword) {
                self.record_failure();
            }
            return Err(open_err(e));
        }
        self.record_success();
        let nctx = format::new_ctx(); // new salt
        let nkey = format::derive_key(new, &nctx)?;
        self.with_unlocked(|g| {
            let bytes = format::encrypt(g.data.as_ref().unwrap(), &nkey, &nctx)?;
            atomic_write(&self.path(), &bytes)?;
            g.key = Some(nkey);
            g.ctx = Some(nctx);
            Ok(())
        })
    }

    pub fn set_auto_lock(&self, secs: u64) -> Result<(), String> {
        atomic_write(&self.dir.join(CFG_FILE), secs.to_string().as_bytes())?;
        let mut g = self.g();
        g.auto_lock_secs = secs;
        if g.key.is_some() {
            g.last_used = Some(Instant::now());
        }
        Ok(())
    }

    /// Export an encrypted backup. `backup_password` None => same master key/salt as the vault.
    pub fn export_backup(&self, dest: &Path, backup_password: Option<&str>) -> Result<(), String> {
        let sep = match backup_password {
            Some(p) => {
                check_password(p)?;
                let c = format::new_ctx();
                let k = format::derive_key(p, &c)?;
                Some((k, c))
            }
            None => None,
        };
        let bytes = self.with_unlocked(|g| match &sep {
            Some((k, c)) => format::encrypt(g.data.as_ref().unwrap(), k, c),
            None => format::encrypt(g.data.as_ref().unwrap(), g.key.as_ref().unwrap(), g.ctx.as_ref().unwrap()),
        })?;
        atomic_write(dest, &bytes)
    }

    /// Import a backup; returns the number of entries imported. `merge=false` replaces everything.
    pub fn import_backup(&self, src: &Path, backup_password: Option<&str>, merge: bool) -> Result<usize, String> {
        if !self.is_unlocked() {
            return Err("vault locked".into());
        }
        let file = fs::read(src).map_err(|e| format!("cannot read backup: {e}"))?;
        let bctx = format::parse_ctx(&file).map_err(open_err)?;
        let key: Key = match backup_password {
            Some(p) => format::derive_key(p, &bctx)?,
            None => {
                // Same-master backup: only valid if it shares the current vault's salt/params.
                let g = self.g();
                match (&g.key, &g.ctx) {
                    (Some(k), Some(c)) if c.salt == bctx.salt => zeroize::Zeroizing::new(**k),
                    _ => return Err("backup password required".into()),
                }
            }
        };
        let incoming = format::decrypt(&file, &key).map_err(open_err)?;
        let count = incoming.entries.len();
        self.with_unlocked(|g| {
            let data = g.data.as_mut().unwrap();
            let snapshot: Vec<(String, Entry)> = data.entries.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            if !merge {
                data.entries.clear();
            }
            for (id, e) in incoming.entries.iter() {
                // On merge, keep whichever entry is newer.
                let keep_existing = merge && data.entries.get(id).map_or(false, |x| x.updated_at > e.updated_at);
                if !keep_existing {
                    data.entries.insert(id.clone(), e.clone());
                }
            }
            if let Err(e) = self.persist(g) {
                let data = g.data.as_mut().unwrap();
                data.entries.clear();
                for (k, v) in snapshot {
                    data.entries.insert(k, v);
                }
                return Err(e);
            }
            Ok(count)
        })
    }
}

// ---------- process-wide singleton ----------

static GLOBAL: OnceLock<Vault> = OnceLock::new();

/// The vault stored under `nora-data/vault` (next to the exe). Starts the auto-lock timer once.
pub fn global() -> Result<&'static Vault, String> {
    if let Some(v) = GLOBAL.get() {
        return Ok(v);
    }
    let dir = crate::portable::data_subdir("vault")?;
    let v = GLOBAL.get_or_init(|| Vault::new(dir));
    static TIMER: std::sync::Once = std::sync::Once::new();
    TIMER.call_once(|| {
        let _ = std::thread::Builder::new().name("vault-autolock".into()).spawn(|| loop {
            std::thread::sleep(Duration::from_secs(1));
            if let Some(v) = GLOBAL.get() {
                v.tick();
            }
        });
    });
    Ok(v)
}

/// True when the vault is currently unlocked (false if never initialized).
pub fn is_unlocked() -> bool {
    GLOBAL.get().map_or(false, |v| v.is_unlocked())
}

/// Resolve a secret by id for INTERNAL Rust use (remote connections). Never exposed to the frontend.
/// The vault must be unlocked; otherwise returns Err("vault locked"). Resets the auto-lock timer.
pub fn resolve_secret(_app: &tauri::AppHandle, id: &str) -> Result<Zeroizing<String>, String> {
    global()?.resolve(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tdir(name: &str) -> PathBuf {
        let d = Path::new(env!("CARGO_MANIFEST_DIR")).join("target").join("vault-tests").join(name);
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn roundtrip() {
        let d = tdir("roundtrip");
        let v = Vault::new(d.clone());
        v.create("correct horse").unwrap();
        v.set("srv1", "s3cret", Some("Server"), Some("password")).unwrap();
        assert_eq!(&*v.resolve("srv1").unwrap(), "s3cret");
        v.lock();
        assert_eq!(v.resolve("srv1").unwrap_err(), "vault locked");
        let v2 = Vault::new(d);
        v2.unlock("correct horse").unwrap();
        assert_eq!(&*v2.resolve("srv1").unwrap(), "s3cret");
        assert_eq!(v2.list().unwrap()[0].label, "Server");
        v2.delete("srv1").unwrap();
        assert!(!v2.has("srv1").unwrap());
    }

    #[test]
    fn wrong_password_and_backoff() {
        let d = tdir("wrong");
        let v = Vault::new(d);
        v.create("correct horse").unwrap();
        v.lock();
        assert_eq!(v.unlock("bad password").unwrap_err(), "wrong password");
        assert_eq!(v.unlock("bad password").unwrap_err(), "wrong password");
        assert_eq!(v.unlock("bad password").unwrap_err(), "wrong password");
        assert!(v.unlock("correct horse").unwrap_err().starts_with("too many attempts"));
    }

    #[test]
    fn change_master() {
        let d = tdir("change");
        let v = Vault::new(d.clone());
        v.create("old password").unwrap();
        v.set("a", "1", None, None).unwrap();
        assert_eq!(v.change_master("nope nope", "new password").unwrap_err(), "wrong password");
        v.change_master("old password", "new password").unwrap();
        v.lock();
        let v2 = Vault::new(d);
        assert_eq!(v2.unlock("old password").unwrap_err(), "wrong password");
        v2.unlock("new password").unwrap();
        assert_eq!(&*v2.resolve("a").unwrap(), "1");
    }

    #[test]
    fn tampered_and_garbage() {
        let d = tdir("tamper");
        let v = Vault::new(d.clone());
        v.create("correct horse").unwrap();
        v.set("a", "1", None, None).unwrap();
        v.lock();
        let p = d.join(VAULT_FILE);
        let good = fs::read(&p).unwrap();
        let mut bad = good.clone();
        let n = bad.len();
        bad[n - 1] ^= 1; // flip a body tag bit: verifier still ok => corrupted
        fs::write(&p, &bad).unwrap();
        assert_eq!(Vault::new(d.clone()).unlock("correct horse").unwrap_err(), "vault file corrupted");
        fs::write(&p, b"garbage").unwrap();
        assert_eq!(Vault::new(d.clone()).unlock("correct horse").unwrap_err(), "vault file corrupted");
        // header tampering is rejected too (AAD-bound)
        let mut bad2 = good;
        bad2[19] ^= 1;
        fs::write(&p, &bad2).unwrap();
        assert!(Vault::new(d).unlock("correct horse").is_err());
    }

    #[test]
    fn backup_export_import() {
        let d = tdir("backup");
        let v = Vault::new(d.clone());
        v.create("correct horse").unwrap();
        v.set("a", "1", Some("A"), None).unwrap();
        let b1 = d.join("same.bak");
        let b2 = d.join("pw.bak");
        v.export_backup(&b1, None).unwrap();
        v.export_backup(&b2, Some("backup pass")).unwrap();
        v.delete("a").unwrap();
        assert_eq!(v.import_backup(&b1, None, true).unwrap(), 1);
        assert_eq!(&*v.resolve("a").unwrap(), "1");
        // other vault (different salt/master) needs the backup password
        let v2 = Vault::new(tdir("backup2"));
        v2.create("another pass").unwrap();
        v2.set("z", "9", None, None).unwrap();
        assert_eq!(v2.import_backup(&b1, None, true).unwrap_err(), "backup password required");
        assert_eq!(v2.import_backup(&b2, Some("wrong pass!"), true).unwrap_err(), "wrong password");
        assert_eq!(v2.import_backup(&b2, Some("backup pass"), true).unwrap(), 1);
        assert!(v2.has("z").unwrap() && v2.has("a").unwrap());
        v2.import_backup(&b2, Some("backup pass"), false).unwrap();
        assert!(!v2.has("z").unwrap());
    }

    #[test]
    fn auto_lock() {
        let v = Vault::new(tdir("autolock"));
        v.create("correct horse").unwrap();
        v.set_auto_lock(1).unwrap();
        std::thread::sleep(Duration::from_millis(1200));
        v.tick();
        assert!(!v.is_unlocked());
    }
}
