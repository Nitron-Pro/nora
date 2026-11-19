//! On-disk format + crypto primitives for the vault (no global state here).
//!
//! Layout (all integers little-endian):
//! `magic "NORAVLT" (7) | version u8 | m_cost_kib u32 | t_cost u32 | lanes u32 | salt[16]
//!  | verifier_nonce[24] | verifier[VERIFIER_LEN] | body_nonce[24] | body ciphertext+tag`
//! The whole header is bound as AEAD associated data of both blobs, so any header tampering fails.
//! The "verifier" is a tiny AEAD blob under the same key: it lets us tell "wrong password"
//! (verifier fails) from "corrupted file" (verifier ok, body fails) without leaking more.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

pub const MAGIC: &[u8; 7] = b"NORAVLT";
pub const FORMAT_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const VERIFIER_PLAIN: &[u8] = b"nora-vault-ok";
const VERIFIER_LEN: usize = 13 + TAG_LEN;
const HEADER_LEN: usize = 7 + 1 + 12 + SALT_LEN; // up to and including salt
const MIN_LEN: usize = HEADER_LEN + NONCE_LEN + VERIFIER_LEN + NONCE_LEN + TAG_LEN;

/// Argon2id parameters stored in the header (so they can be raised in future versions).
#[derive(Clone, Copy, Debug)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub lanes: u32,
}

#[cfg(not(test))]
pub const DEFAULT_PARAMS: KdfParams = KdfParams { m_kib: 65536, t: 3, lanes: 1 };
// Cheap parameters keep unit tests fast; production builds always use the strong set.
#[cfg(test)]
pub const DEFAULT_PARAMS: KdfParams = KdfParams { m_kib: 256, t: 1, lanes: 1 };

/// A single stored secret. Zeroized on drop.
#[derive(Serialize, Deserialize, Clone)]
pub struct Entry {
    pub secret: String,
    pub label: String,
    pub kind: String,
    pub updated_at: i64,
}
impl Drop for Entry {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Decrypted vault contents. Ids/labels/secrets are all inside the encrypted blob.
#[derive(Serialize, Deserialize, Default)]
pub struct VaultData {
    pub entries: BTreeMap<String, Entry>,
}

pub type Key = Zeroizing<[u8; 32]>;

/// Header facts needed to re-encrypt with the same key (salt + params).
#[derive(Clone, Copy)]
pub struct KeyCtx {
    pub salt: [u8; SALT_LEN],
    pub params: KdfParams,
}

pub enum OpenError {
    /// Not a vault file / truncated / unsupported version / body fails after a valid verifier.
    Corrupt,
    WrongPassword,
}

pub fn new_ctx() -> KeyCtx {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    KeyCtx { salt, params: DEFAULT_PARAMS }
}

pub fn derive_key(password: &str, ctx: &KeyCtx) -> Result<Key, String> {
    let params = Params::new(ctx.params.m_kib, ctx.params.t, ctx.params.lanes, Some(32))
        .map_err(|_| "invalid KDF parameters".to_string())?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), &ctx.salt, &mut *out)
        .map_err(|_| "key derivation failed".to_string())?;
    Ok(out)
}

fn header_bytes(ctx: &KeyCtx) -> Vec<u8> {
    let mut h = Vec::with_capacity(HEADER_LEN);
    h.extend_from_slice(MAGIC);
    h.push(FORMAT_VERSION);
    h.extend_from_slice(&ctx.params.m_kib.to_le_bytes());
    h.extend_from_slice(&ctx.params.t.to_le_bytes());
    h.extend_from_slice(&ctx.params.lanes.to_le_bytes());
    h.extend_from_slice(&ctx.salt);
    h
}

fn cipher(key: &Key) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(&key[..]).expect("32-byte key")
}

fn seal(key: &Key, aad: &[u8], plain: &[u8]) -> Result<([u8; NONCE_LEN], Vec<u8>), String> {
    let mut n = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut n); // fresh random nonce for EVERY write
    let nonce = XNonce::try_from(&n[..]).map_err(|_| "nonce error".to_string())?;
    let ct = cipher(key)
        .encrypt(&nonce, Payload { msg: plain, aad })
        .map_err(|_| "encryption failed".to_string())?;
    Ok((n, ct))
}

fn open_blob(key: &Key, aad: &[u8], nonce: &[u8], ct: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let nonce = XNonce::try_from(nonce).ok()?;
    cipher(key).decrypt(&nonce, Payload { msg: ct, aad }).ok().map(Zeroizing::new)
}

/// Serialize + encrypt the vault with an already-derived key.
pub fn encrypt(data: &VaultData, key: &Key, ctx: &KeyCtx) -> Result<Vec<u8>, String> {
    let json = Zeroizing::new(serde_json::to_vec(data).map_err(|e| format!("serialize: {e}"))?);
    let header = header_bytes(ctx);
    let (vn, vct) = seal(key, &header, VERIFIER_PLAIN)?;
    let (bn, bct) = seal(key, &header, &json)?;
    let mut out = header;
    out.extend_from_slice(&vn);
    out.extend_from_slice(&vct);
    out.extend_from_slice(&bn);
    out.extend_from_slice(&bct);
    Ok(out)
}

/// Parse the (unauthenticated) header to learn salt/params. Bounds-checked to avoid KDF DoS.
pub fn parse_ctx(file: &[u8]) -> Result<KeyCtx, OpenError> {
    if file.len() < MIN_LEN || &file[..7] != MAGIC || file[7] != FORMAT_VERSION {
        return Err(OpenError::Corrupt);
    }
    let u = |o: usize| u32::from_le_bytes(file[o..o + 4].try_into().unwrap());
    let params = KdfParams { m_kib: u(8), t: u(12), lanes: u(16) };
    if params.m_kib < 8 || params.m_kib > 1 << 20 || params.t == 0 || params.t > 32 || params.lanes == 0 || params.lanes > 16 {
        return Err(OpenError::Corrupt);
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&file[20..20 + SALT_LEN]);
    Ok(KeyCtx { salt, params })
}

/// Decrypt with a derived key. Distinguishes wrong key from corruption via the verifier.
pub fn decrypt(file: &[u8], key: &Key) -> Result<VaultData, OpenError> {
    parse_ctx(file)?;
    let aad = &file[..HEADER_LEN];
    let mut o = HEADER_LEN;
    let vn = &file[o..o + NONCE_LEN];
    o += NONCE_LEN;
    let vct = &file[o..o + VERIFIER_LEN];
    o += VERIFIER_LEN;
    let bn = &file[o..o + NONCE_LEN];
    o += NONCE_LEN;
    let bct = &file[o..];
    match open_blob(key, aad, vn, vct) {
        Some(v) if v.as_slice() == VERIFIER_PLAIN => {}
        _ => return Err(OpenError::WrongPassword),
    }
    let plain = open_blob(key, aad, bn, bct).ok_or(OpenError::Corrupt)?;
    serde_json::from_slice::<VaultData>(&plain).map_err(|_| OpenError::Corrupt)
}
