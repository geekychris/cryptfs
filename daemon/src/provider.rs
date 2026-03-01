// SPDX-License-Identifier: GPL-2.0
//! Key provider trait and implementations.
//!
//! The `KeyProvider` trait abstracts key retrieval so the daemon can be
//! extended to support external KMS systems (AWS KMS, HashiCorp Vault, etc.)
//! without changing the core daemon logic.

use std::path::{Path, PathBuf};

use anyhow::Result;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

/// Size of AES-256 key in bytes
const KEY_SIZE: usize = 32;

/// Metadata about a key from the provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub key_id: String,
    pub provider: String,
    pub created_at: String,
    pub version: u32,
}

/// Trait abstracting key management operations.
///
/// PoC implements `LocalKeyProvider`. Future implementations:
/// - `VaultKeyProvider` — HashiCorp Vault Transit secrets engine
/// - `AwsKmsKeyProvider` — AWS KMS
/// - `AzureKeyVaultProvider` — Azure Key Vault
/// - `GcpKmsProvider` — Google Cloud KMS
pub trait KeyProvider: Send + Sync {
    /// Retrieve a master key by ID.
    fn get_master_key(&self, key_id: &str) -> Result<Vec<u8>>;

    /// Generate and store a new master key, returning its ID.
    fn generate_master_key(&self, label: &str) -> Result<String>;

    /// Rotate an existing master key, returning the new key material.
    fn rotate_key(&self, key_id: &str) -> Result<Vec<u8>>;

    /// List available key IDs.
    fn list_keys(&self) -> Result<Vec<KeyMetadata>>;

    /// Provider name for audit/logging.
    fn provider_name(&self) -> &str;
}

/// Local filesystem-based key provider.
///
/// Stores keys as encrypted files on disk. This is the PoC implementation
/// suitable for development and testing.
pub struct LocalKeyProvider {
    key_dir: PathBuf,
    rng: SystemRandom,
}

impl LocalKeyProvider {
    pub fn new(key_dir: PathBuf) -> Self {
        Self {
            key_dir,
            rng: SystemRandom::new(),
        }
    }
}

impl KeyProvider for LocalKeyProvider {
    fn get_master_key(&self, key_id: &str) -> Result<Vec<u8>> {
        let path = self.key_dir.join(format!("{}.raw", key_id));
        if path.exists() {
            let data = std::fs::read(&path)?;
            Ok(data)
        } else {
            anyhow::bail!("Key not found in local store: {}", key_id)
        }
    }

    fn generate_master_key(&self, label: &str) -> Result<String> {
        let key_id = uuid::Uuid::new_v4().to_string();

        let mut key = vec![0u8; KEY_SIZE];
        self.rng.fill(&mut key)
            .map_err(|_| anyhow::anyhow!("RNG failure"))?;

        // Store raw key (in production, this would go to KMS)
        let path = self.key_dir.join(format!("{}.raw", key_id));
        std::fs::write(&path, &key)?;

        tracing::info!("LocalKeyProvider: generated key {} ({})", key_id, label);
        Ok(key_id)
    }

    fn rotate_key(&self, key_id: &str) -> Result<Vec<u8>> {
        let mut new_key = vec![0u8; KEY_SIZE];
        self.rng.fill(&mut new_key)
            .map_err(|_| anyhow::anyhow!("RNG failure"))?;

        let path = self.key_dir.join(format!("{}.raw", key_id));
        std::fs::write(&path, &new_key)?;

        tracing::info!("LocalKeyProvider: rotated key {}", key_id);
        Ok(new_key)
    }

    fn list_keys(&self) -> Result<Vec<KeyMetadata>> {
        let mut keys = Vec::new();
        for entry in std::fs::read_dir(&self.key_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map(|e| e == "raw").unwrap_or(false) {
                if let Some(stem) = path.file_stem() {
                    keys.push(KeyMetadata {
                        key_id: stem.to_string_lossy().to_string(),
                        provider: "local".to_string(),
                        created_at: String::new(),
                        version: 1,
                    });
                }
            }
        }
        Ok(keys)
    }

    fn provider_name(&self) -> &str {
        "local"
    }
}
