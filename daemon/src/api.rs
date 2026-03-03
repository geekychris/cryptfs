// SPDX-License-Identifier: GPL-2.0
//! Unix domain socket API for the CryptoFS daemon.
//!
//! Provides a JSON-over-Unix-socket protocol for the admin CLI to
//! communicate with the daemon. Each request is a single JSON line
//! and each response is a single JSON line.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::audit::AuditEvent;
use crate::keyring;
use crate::DaemonState;

/// API request types
#[derive(Debug, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum ApiRequest {
    /// Generate a new master key
    KeyGenerate {
        label: String,
        passphrase: String,
    },
    /// Unlock an existing key
    KeyUnlock {
        key_id: String,
        passphrase: String,
    },
    /// Lock (re-encrypt and remove from memory) a key
    KeyLock {
        key_id: String,
    },
    /// Activate a key (inject into kernel keyring)
    KeyActivate {
        key_id: String,
    },
    /// Deactivate a key (revoke from kernel keyring)
    KeyDeactivate {
        key_id: String,
        serial: i32,
    },
    /// Rotate a key
    KeyRotate {
        key_id: String,
        passphrase: String,
    },
    /// Import a raw key
    KeyImport {
        label: String,
        passphrase: String,
        /// Hex-encoded raw key
        key_hex: String,
    },
    /// Delete a key
    KeyDelete {
        key_id: String,
    },
    /// List all keys
    KeyList,
    /// Get key info
    KeyInfo {
        key_id: String,
    },
    /// Get daemon status
    Status,
    /// Get recent audit events
    AuditList {
        count: Option<usize>,
    },
    /// Unlock a key and return material for session-keyring injection
    SessionUnlock {
        key_id: String,
        passphrase: String,
        timeout: Option<u32>,
    },
}

/// API response
#[derive(Debug, Serialize)]
pub struct ApiResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ApiResponse {
    fn ok(data: serde_json::Value) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn ok_empty() -> Self {
        Self {
            success: true,
            data: None,
            error: None,
        }
    }

    fn err(msg: impl ToString) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(msg.to_string()),
        }
    }
}

/// Start the Unix socket API server.
pub async fn serve(socket_path: PathBuf, state: Arc<RwLock<DaemonState>>) -> Result<()> {
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("Failed to bind to {}", socket_path.display()))?;

    // Set socket permissions (owner + group read/write)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o660))?;
    }

    info!("API server listening on {}", socket_path.display());

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, state).await {
                        error!("Client handler error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Accept error: {}", e);
            }
        }
    }
}

/// Handle a single client connection.
async fn handle_client(
    stream: tokio::net::UnixStream,
    state: Arc<RwLock<DaemonState>>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);

    let mut line = String::new();
    loop {
        line.clear();
        let n = buf_reader.read_line(&mut line).await?;
        if n == 0 {
            break; // Client disconnected
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        debug!("Received request: {}", trimmed);

        let response = match serde_json::from_str::<ApiRequest>(trimmed) {
            Ok(request) => handle_request(request, &state).await,
            Err(e) => ApiResponse::err(format!("Invalid request: {}", e)),
        };

        let mut resp_json = serde_json::to_string(&response)?;
        resp_json.push('\n');
        writer.write_all(resp_json.as_bytes()).await?;
        writer.flush().await?;
    }

    Ok(())
}

/// Dispatch and handle a single API request.
async fn handle_request(
    request: ApiRequest,
    state: &Arc<RwLock<DaemonState>>,
) -> ApiResponse {
    match request {
        ApiRequest::KeyGenerate { label, passphrase } => {
            let mut state = state.write().await;
            match state.keystore.generate_key(&label, &passphrase) {
                Ok(key_id) => {
                    state.audit.log(AuditEvent::key_generated(&key_id, &label));
                    ApiResponse::ok(serde_json::json!({ "key_id": key_id }))
                }
                Err(e) => ApiResponse::err(e),
            }
        }

        ApiRequest::KeyUnlock { key_id, passphrase } => {
            let mut state = state.write().await;
            match state.keystore.unlock_key(&key_id, &passphrase) {
                Ok(()) => {
                    state.audit.log(AuditEvent::key_unlocked(&key_id));
                    ApiResponse::ok_empty()
                }
                Err(e) => ApiResponse::err(e),
            }
        }

        ApiRequest::KeyLock { key_id } => {
            let mut state = state.write().await;
            state.keystore.lock_key(&key_id);
            state.audit.log(AuditEvent::key_locked(&key_id));
            ApiResponse::ok_empty()
        }

        ApiRequest::KeyActivate { key_id } => {
            let state = state.read().await;
            match state.keystore.get_key(&key_id) {
                Ok(key_data) => {
                    match keyring::activate_key(&key_id, &key_data) {
                        Ok(kr_key) => {
                            state.audit.log(AuditEvent::key_activated(&key_id));
                            ApiResponse::ok(serde_json::json!({
                                "key_id": key_id,
                                "serial": kr_key.serial,
                                "description": kr_key.description,
                            }))
                        }
                        Err(e) => ApiResponse::err(e),
                    }
                }
                Err(e) => ApiResponse::err(format!("Key not unlocked: {}", e)),
            }
        }

        ApiRequest::KeyDeactivate { key_id, serial } => {
            let state = state.read().await;
            match keyring::deactivate_key(serial, &key_id) {
                Ok(()) => {
                    state.audit.log(AuditEvent::key_deactivated(&key_id));
                    ApiResponse::ok_empty()
                }
                Err(e) => ApiResponse::err(e),
            }
        }

        ApiRequest::KeyRotate { key_id, passphrase } => {
            let mut state = state.write().await;
            match state.keystore.rotate_key(&key_id, &passphrase) {
                Ok(()) => {
                    let version = state.keystore
                        .get_key_info(&key_id)
                        .map(|k| k.version)
                        .unwrap_or(0);
                    state.audit.log(AuditEvent::key_rotated(&key_id, version));
                    ApiResponse::ok(serde_json::json!({
                        "key_id": key_id,
                        "version": version,
                    }))
                }
                Err(e) => ApiResponse::err(e),
            }
        }

        ApiRequest::KeyImport { label, passphrase, key_hex } => {
            let raw_key = match hex_decode(&key_hex) {
                Ok(k) => k,
                Err(e) => return ApiResponse::err(format!("Invalid hex key: {}", e)),
            };
            let mut state = state.write().await;
            match state.keystore.import_key(&label, &passphrase, &raw_key) {
                Ok(key_id) => {
                    state.audit.log(AuditEvent::key_imported(&key_id, &label));
                    ApiResponse::ok(serde_json::json!({ "key_id": key_id }))
                }
                Err(e) => ApiResponse::err(e),
            }
        }

        ApiRequest::KeyDelete { key_id } => {
            let mut state = state.write().await;
            match state.keystore.delete_key(&key_id) {
                Ok(()) => {
                    state.audit.log(AuditEvent::key_deleted(&key_id));
                    ApiResponse::ok_empty()
                }
                Err(e) => ApiResponse::err(e),
            }
        }

        ApiRequest::KeyList => {
            let state = state.read().await;
            let keys: Vec<_> = state.keystore.list_keys().iter().map(|k| {
                serde_json::json!({
                    "key_id": k.key_id,
                    "label": k.label,
                    "version": k.version,
                    "active": k.active,
                    "created_at": k.created_at.to_rfc3339(),
                    "rotated_at": k.rotated_at.map(|t| t.to_rfc3339()),
                })
            }).collect();
            ApiResponse::ok(serde_json::json!({ "keys": keys }))
        }

        ApiRequest::KeyInfo { key_id } => {
            let state = state.read().await;
            match state.keystore.get_key_info(&key_id) {
                Some(k) => ApiResponse::ok(serde_json::json!({
                    "key_id": k.key_id,
                    "label": k.label,
                    "version": k.version,
                    "active": k.active,
                    "created_at": k.created_at.to_rfc3339(),
                    "rotated_at": k.rotated_at.map(|t| t.to_rfc3339()),
                })),
                None => ApiResponse::err(format!("Key not found: {}", key_id)),
            }
        }

        ApiRequest::Status => {
            let state = state.read().await;
            let key_count = state.keystore.list_keys().len();
            let provider = state.provider.provider_name();
            ApiResponse::ok(serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "key_count": key_count,
                "provider": provider,
                "pid": std::process::id(),
            }))
        }

        ApiRequest::AuditList { count } => {
            let state = state.read().await;
            let events = state.audit.recent(count.unwrap_or(50));
            let events_json: Vec<_> = events.iter().map(|e| {
                serde_json::json!({
                    "timestamp": e.timestamp,
                    "event_type": e.event_type,
                    "key_id": e.key_id,
                    "details": e.details,
                })
            }).collect();
            ApiResponse::ok(serde_json::json!({ "events": events_json }))
        }

        ApiRequest::SessionUnlock { key_id, passphrase, timeout } => {
            let mut state = state.write().await;
            if let Err(e) = state.keystore.unlock_key(&key_id, &passphrase) {
                return ApiResponse::err(format!("Failed to unlock: {}", e));
            }
            match state.keystore.get_key(&key_id) {
                Ok(key_data) => {
                    state.audit.log(AuditEvent::key_unlocked(&key_id));
                    ApiResponse::ok(serde_json::json!({
                        "key_id": key_id,
                        "key_hex": hex_encode(&key_data),
                        "timeout": timeout.unwrap_or(0),
                    }))
                }
                Err(e) => ApiResponse::err(format!("Key not available: {}", e)),
            }
        }
    }
}

/// Simple hex encoder
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Simple hex decoder (avoids adding another dependency)
fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    let hex = hex.trim();
    if hex.len() % 2 != 0 {
        anyhow::bail!("Odd-length hex string");
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("Invalid hex at position {}: {}", i, e))
        })
        .collect()
}
