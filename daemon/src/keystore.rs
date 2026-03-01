// SPDX-License-Identifier: GPL-2.0
//! Local key storage with encryption at rest.
//!
//! Master keys are stored encrypted using a KEK derived from a passphrase
//! via Argon2id. Each key file is a JSON document containing the encrypted
//! key material, salt, and metadata.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use ring::aead::{self, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Size of AES-256 key in bytes
const KEY_SIZE: usize = 32;

/// Size of AES-GCM nonce in bytes
const NONCE_SIZE: usize = 12;

/// Size of Argon2id salt
const SALT_SIZE: usize = 32;

/// Stored key metadata + encrypted material
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKey {
    /// Unique key identifier
    pub key_id: String,
    /// Human-readable label
    pub label: String,
    /// When the key was created
    pub created_at: DateTime<Utc>,
    /// When the key was last rotated (if ever)
    pub rotated_at: Option<DateTime<Utc>>,
    /// Key version (incremented on rotation)
    pub version: u32,
    /// Argon2id salt for KEK derivation (base64)
    pub salt: String,
    /// AES-GCM nonce used to encrypt the key material (base64)
    pub nonce: String,
    /// Encrypted key material (base64, AES-256-GCM ciphertext + tag)
    pub encrypted_key: String,
    /// Whether the key is currently active
    pub active: bool,
}

/// In-memory cache of decrypted keys (cleared on daemon shutdown)
struct DecryptedKeyCache {
    keys: HashMap<String, Vec<u8>>,
}

impl DecryptedKeyCache {
    fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    fn get(&self, key_id: &str) -> Option<&[u8]> {
        self.keys.get(key_id).map(|v| v.as_slice())
    }

    fn insert(&mut self, key_id: String, key: Vec<u8>) {
        self.keys.insert(key_id, key);
    }

    fn remove(&mut self, key_id: &str) {
        if let Some(mut key) = self.keys.remove(key_id) {
            // Zero out before dropping
            key.iter_mut().for_each(|b| *b = 0);
        }
    }
}

impl Drop for DecryptedKeyCache {
    fn drop(&mut self) {
        // Zero all cached keys
        for (_, key) in self.keys.iter_mut() {
            key.iter_mut().for_each(|b| *b = 0);
        }
    }
}

pub struct KeyStore {
    key_dir: PathBuf,
    /// Stored key metadata indexed by key_id
    keys: HashMap<String, StoredKey>,
    /// In-memory decrypted key cache
    cache: DecryptedKeyCache,
    rng: SystemRandom,
}

impl KeyStore {
    /// Open or create a key store at the given directory.
    pub fn new(key_dir: &Path) -> Result<Self> {
        fs::create_dir_all(key_dir)
            .with_context(|| format!("Cannot create key dir: {}", key_dir.display()))?;

        let mut store = Self {
            key_dir: key_dir.to_owned(),
            keys: HashMap::new(),
            cache: DecryptedKeyCache::new(),
            rng: SystemRandom::new(),
        };

        store.load_metadata()?;
        Ok(store)
    }

    /// Load all key metadata from disk (not the decrypted keys).
    fn load_metadata(&mut self) -> Result<()> {
        for entry in fs::read_dir(&self.key_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                let data = fs::read_to_string(&path)
                    .with_context(|| format!("Reading key file {}", path.display()))?;
                match serde_json::from_str::<StoredKey>(&data) {
                    Ok(key) => {
                        self.keys.insert(key.key_id.clone(), key);
                    }
                    Err(e) => {
                        tracing::warn!("Skipping invalid key file {}: {}", path.display(), e);
                    }
                }
            }
        }
        tracing::info!("Loaded {} key(s) from {}", self.keys.len(), self.key_dir.display());
        Ok(())
    }

    /// Generate a new master key, encrypt it with the passphrase, and store it.
    pub fn generate_key(&mut self, label: &str, passphrase: &str) -> Result<String> {
        let key_id = Uuid::new_v4().to_string();

        // Generate random master key
        let mut master_key = vec![0u8; KEY_SIZE];
        self.rng.fill(&mut master_key)
            .map_err(|_| anyhow::anyhow!("RNG failure"))?;

        // Generate salt for Argon2id
        let mut salt = vec![0u8; SALT_SIZE];
        self.rng.fill(&mut salt)
            .map_err(|_| anyhow::anyhow!("RNG failure"))?;

        // Derive KEK from passphrase
        let kek = derive_kek(passphrase, &salt)?;

        // Generate nonce for encrypting the master key
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        self.rng.fill(&mut nonce_bytes)
            .map_err(|_| anyhow::anyhow!("RNG failure"))?;

        // Encrypt master key with KEK
        let encrypted = encrypt_key_material(&kek, &nonce_bytes, &master_key)?;

        let stored = StoredKey {
            key_id: key_id.clone(),
            label: label.to_string(),
            created_at: Utc::now(),
            rotated_at: None,
            version: 1,
            salt: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &salt),
            nonce: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &nonce_bytes),
            encrypted_key: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &encrypted),
            active: true,
        };

        // Save to disk
        self.save_key(&stored)?;

        // Cache decrypted key
        self.cache.insert(key_id.clone(), master_key);
        self.keys.insert(key_id.clone(), stored);

        tracing::info!("Generated new key: {} ({})", key_id, label);
        Ok(key_id)
    }

    /// Unlock (decrypt) a stored key with the passphrase and cache it.
    pub fn unlock_key(&mut self, key_id: &str, passphrase: &str) -> Result<()> {
        if self.cache.get(key_id).is_some() {
            return Ok(()); // Already unlocked
        }

        let stored = self.keys.get(key_id)
            .ok_or_else(|| anyhow::anyhow!("Key not found: {}", key_id))?
            .clone();

        use base64::Engine;
        let salt = base64::engine::general_purpose::STANDARD.decode(&stored.salt)?;
        let nonce_bytes = base64::engine::general_purpose::STANDARD.decode(&stored.nonce)?;
        let encrypted = base64::engine::general_purpose::STANDARD.decode(&stored.encrypted_key)?;

        let kek = derive_kek(passphrase, &salt)?;
        let master_key = decrypt_key_material(&kek, &nonce_bytes, &encrypted)?;

        self.cache.insert(key_id.to_string(), master_key);
        tracing::info!("Unlocked key: {}", key_id);
        Ok(())
    }

    /// Get a decrypted key from cache (must be unlocked first).
    pub fn get_key(&self, key_id: &str) -> Result<Vec<u8>> {
        self.cache.get(key_id)
            .map(|k| k.to_vec())
            .ok_or_else(|| anyhow::anyhow!("Key {} not unlocked", key_id))
    }

    /// Lock a key (remove from cache).
    pub fn lock_key(&mut self, key_id: &str) {
        self.cache.remove(key_id);
        tracing::info!("Locked key: {}", key_id);
    }

    /// List all stored keys (metadata only).
    pub fn list_keys(&self) -> Vec<&StoredKey> {
        self.keys.values().collect()
    }

    /// Get metadata for a specific key.
    pub fn get_key_info(&self, key_id: &str) -> Option<&StoredKey> {
        self.keys.get(key_id)
    }

    /// Rotate a key: generate new key material, re-encrypt with same passphrase.
    pub fn rotate_key(&mut self, key_id: &str, passphrase: &str) -> Result<()> {
        let stored = self.keys.get(key_id)
            .ok_or_else(|| anyhow::anyhow!("Key not found: {}", key_id))?
            .clone();

        // Generate new master key
        let mut new_key = vec![0u8; KEY_SIZE];
        self.rng.fill(&mut new_key)
            .map_err(|_| anyhow::anyhow!("RNG failure"))?;

        // New salt and nonce
        let mut salt = vec![0u8; SALT_SIZE];
        self.rng.fill(&mut salt)
            .map_err(|_| anyhow::anyhow!("RNG failure"))?;

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        self.rng.fill(&mut nonce_bytes)
            .map_err(|_| anyhow::anyhow!("RNG failure"))?;

        let kek = derive_kek(passphrase, &salt)?;
        let encrypted = encrypt_key_material(&kek, &nonce_bytes, &new_key)?;

        let updated = StoredKey {
            key_id: key_id.to_string(),
            label: stored.label,
            created_at: stored.created_at,
            rotated_at: Some(Utc::now()),
            version: stored.version + 1,
            salt: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &salt),
            nonce: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &nonce_bytes),
            encrypted_key: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &encrypted),
            active: true,
        };

        self.save_key(&updated)?;
        self.cache.insert(key_id.to_string(), new_key);
        self.keys.insert(key_id.to_string(), updated);

        tracing::info!("Rotated key: {} (now v{})", key_id, stored.version + 1);
        Ok(())
    }

    /// Import a raw key (for testing / migration).
    pub fn import_key(&mut self, label: &str, passphrase: &str, raw_key: &[u8]) -> Result<String> {
        if raw_key.len() != KEY_SIZE {
            bail!("Key must be {} bytes, got {}", KEY_SIZE, raw_key.len());
        }

        let key_id = Uuid::new_v4().to_string();

        let mut salt = vec![0u8; SALT_SIZE];
        self.rng.fill(&mut salt)
            .map_err(|_| anyhow::anyhow!("RNG failure"))?;

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        self.rng.fill(&mut nonce_bytes)
            .map_err(|_| anyhow::anyhow!("RNG failure"))?;

        let kek = derive_kek(passphrase, &salt)?;
        let encrypted = encrypt_key_material(&kek, &nonce_bytes, raw_key)?;

        let stored = StoredKey {
            key_id: key_id.clone(),
            label: label.to_string(),
            created_at: Utc::now(),
            rotated_at: None,
            version: 1,
            salt: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &salt),
            nonce: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &nonce_bytes),
            encrypted_key: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &encrypted),
            active: true,
        };

        self.save_key(&stored)?;
        self.cache.insert(key_id.clone(), raw_key.to_vec());
        self.keys.insert(key_id.clone(), stored);

        Ok(key_id)
    }

    /// Delete a key from disk and memory.
    pub fn delete_key(&mut self, key_id: &str) -> Result<()> {
        self.cache.remove(key_id);
        self.keys.remove(key_id);

        let path = self.key_dir.join(format!("{}.json", key_id));
        if path.exists() {
            fs::remove_file(&path)?;
        }

        tracing::info!("Deleted key: {}", key_id);
        Ok(())
    }

    fn save_key(&self, key: &StoredKey) -> Result<()> {
        let path = self.key_dir.join(format!("{}.json", key.key_id));
        let data = serde_json::to_string_pretty(key)?;
        fs::write(&path, data)
            .with_context(|| format!("Writing key file {}", path.display()))?;
        Ok(())
    }
}

/// Derive a 256-bit KEK from a passphrase using Argon2id.
fn derive_kek(passphrase: &str, salt: &[u8]) -> Result<Vec<u8>> {
    use argon2::{Argon2, Algorithm, Version, Params};

    let params = Params::new(
        65536,  // 64 MB memory
        3,      // 3 iterations
        4,      // 4 parallelism
        Some(KEY_SIZE),
    ).map_err(|e| anyhow::anyhow!("Argon2 params error: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut kek = vec![0u8; KEY_SIZE];
    argon2.hash_password_into(passphrase.as_bytes(), salt, &mut kek)
        .map_err(|e| anyhow::anyhow!("Argon2 hash error: {}", e))?;

    Ok(kek)
}

/// Encrypt key material with KEK using AES-256-GCM.
fn encrypt_key_material(kek: &[u8], nonce_bytes: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let unbound = UnboundKey::new(&AES_256_GCM, kek)
        .map_err(|_| anyhow::anyhow!("Invalid KEK"))?;
    let key = LessSafeKey::new(unbound);

    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
        .map_err(|_| anyhow::anyhow!("Invalid nonce"))?;

    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
        .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

    Ok(in_out)
}

/// Decrypt key material with KEK using AES-256-GCM.
fn decrypt_key_material(kek: &[u8], nonce_bytes: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let unbound = UnboundKey::new(&AES_256_GCM, kek)
        .map_err(|_| anyhow::anyhow!("Invalid KEK"))?;
    let key = LessSafeKey::new(unbound);

    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
        .map_err(|_| anyhow::anyhow!("Invalid nonce"))?;

    let mut in_out = ciphertext.to_vec();
    let plaintext = key.open_in_place(nonce, aead::Aad::empty(), &mut in_out)
        .map_err(|_| anyhow::anyhow!("Decryption failed (bad passphrase?)"))?;

    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_generate_and_unlock_key() {
        let dir = tempdir().unwrap();
        let mut store = KeyStore::new(dir.path()).unwrap();

        let key_id = store.generate_key("test-key", "my-passphrase").unwrap();

        // Key should be in cache immediately after generation
        let key = store.get_key(&key_id).unwrap();
        assert_eq!(key.len(), KEY_SIZE);

        // Lock it
        store.lock_key(&key_id);
        assert!(store.get_key(&key_id).is_err());

        // Unlock with correct passphrase
        store.unlock_key(&key_id, "my-passphrase").unwrap();
        let key2 = store.get_key(&key_id).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn test_wrong_passphrase() {
        let dir = tempdir().unwrap();
        let mut store = KeyStore::new(dir.path()).unwrap();

        let key_id = store.generate_key("test-key", "correct").unwrap();
        store.lock_key(&key_id);

        let result = store.unlock_key(&key_id, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_rotate_key() {
        let dir = tempdir().unwrap();
        let mut store = KeyStore::new(dir.path()).unwrap();

        let key_id = store.generate_key("test-key", "pass").unwrap();
        let key_v1 = store.get_key(&key_id).unwrap();

        store.rotate_key(&key_id, "pass").unwrap();
        let key_v2 = store.get_key(&key_id).unwrap();

        // New key should be different
        assert_ne!(key_v1, key_v2);

        let info = store.get_key_info(&key_id).unwrap();
        assert_eq!(info.version, 2);
        assert!(info.rotated_at.is_some());
    }

    #[test]
    fn test_persistence() {
        let dir = tempdir().unwrap();
        let key_id;

        // Create and store a key
        {
            let mut store = KeyStore::new(dir.path()).unwrap();
            key_id = store.generate_key("persist-test", "pass").unwrap();
        }

        // Reload from disk
        {
            let mut store = KeyStore::new(dir.path()).unwrap();
            assert!(store.get_key_info(&key_id).is_some());

            // Must unlock before use
            assert!(store.get_key(&key_id).is_err());
            store.unlock_key(&key_id, "pass").unwrap();
            let key = store.get_key(&key_id).unwrap();
            assert_eq!(key.len(), KEY_SIZE);
        }
    }

    #[test]
    fn test_kek_derivation() {
        let salt = [0u8; SALT_SIZE];
        let kek1 = derive_kek("password", &salt).unwrap();
        let kek2 = derive_kek("password", &salt).unwrap();
        assert_eq!(kek1, kek2);

        let kek3 = derive_kek("different", &salt).unwrap();
        assert_ne!(kek1, kek3);
    }
}
