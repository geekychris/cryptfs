// SPDX-License-Identifier: GPL-2.0
//! Audit logging for key management operations.
//!
//! Maintains both an in-memory ring buffer (for quick queries) and
//! a persistent log file on disk.

use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Maximum events kept in the in-memory ring buffer
const MAX_MEMORY_EVENTS: usize = 1000;

/// A single audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: String,
    pub event_type: String,
    pub key_id: Option<String>,
    pub details: String,
}

impl AuditEvent {
    fn new(event_type: &str, key_id: Option<&str>, details: &str) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            event_type: event_type.to_string(),
            key_id: key_id.map(|s| s.to_string()),
            details: details.to_string(),
        }
    }

    pub fn key_generated(key_id: &str, label: &str) -> Self {
        Self::new("key_generated", Some(key_id), &format!("label={}", label))
    }

    pub fn key_unlocked(key_id: &str) -> Self {
        Self::new("key_unlocked", Some(key_id), "")
    }

    pub fn key_locked(key_id: &str) -> Self {
        Self::new("key_locked", Some(key_id), "")
    }

    pub fn key_activated(key_id: &str) -> Self {
        Self::new("key_activated", Some(key_id), "injected into kernel keyring")
    }

    pub fn key_deactivated(key_id: &str) -> Self {
        Self::new("key_deactivated", Some(key_id), "revoked from kernel keyring")
    }

    pub fn key_rotated(key_id: &str, version: u32) -> Self {
        Self::new(
            "key_rotated",
            Some(key_id),
            &format!("new_version={}", version),
        )
    }

    pub fn key_imported(key_id: &str, label: &str) -> Self {
        Self::new("key_imported", Some(key_id), &format!("label={}", label))
    }

    pub fn key_deleted(key_id: &str) -> Self {
        Self::new("key_deleted", Some(key_id), "")
    }

    pub fn daemon_started() -> Self {
        Self::new("daemon_started", None, "")
    }

    pub fn daemon_stopped() -> Self {
        Self::new("daemon_stopped", None, "")
    }
}

/// Audit log with in-memory ring buffer and persistent file
pub struct AuditLog {
    events: Mutex<VecDeque<AuditEvent>>,
    log_path: PathBuf,
    log_file: Mutex<Option<fs::File>>,
}

impl AuditLog {
    /// Create a new audit log, opening the file for appending.
    pub fn new(log_path: &Path) -> Result<Self> {
        if let Some(parent) = log_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .with_context(|| format!("Cannot open audit log: {}", log_path.display()))?;

        let log = Self {
            events: Mutex::new(VecDeque::with_capacity(MAX_MEMORY_EVENTS)),
            log_path: log_path.to_owned(),
            log_file: Mutex::new(Some(file)),
        };

        log.log(AuditEvent::daemon_started());
        Ok(log)
    }

    /// Log an audit event (both in-memory and to file).
    pub fn log(&self, event: AuditEvent) {
        // Write to file
        if let Ok(mut guard) = self.log_file.lock() {
            if let Some(ref mut file) = *guard {
                if let Ok(json) = serde_json::to_string(&event) {
                    let _ = writeln!(file, "{}", json);
                }
            }
        }

        // Add to in-memory buffer
        if let Ok(mut events) = self.events.lock() {
            if events.len() >= MAX_MEMORY_EVENTS {
                events.pop_front();
            }
            tracing::debug!(
                "Audit: {} key={:?} {}",
                event.event_type,
                event.key_id,
                event.details
            );
            events.push_back(event);
        }
    }

    /// Get the most recent N events.
    pub fn recent(&self, count: usize) -> Vec<AuditEvent> {
        if let Ok(events) = self.events.lock() {
            let start = events.len().saturating_sub(count);
            events.iter().skip(start).cloned().collect()
        } else {
            Vec::new()
        }
    }

    /// Flush the log file.
    pub fn flush(&self) -> Result<()> {
        if let Ok(mut guard) = self.log_file.lock() {
            if let Some(ref mut file) = *guard {
                file.flush()?;
            }
        }
        Ok(())
    }
}

impl Drop for AuditLog {
    fn drop(&mut self) {
        self.log(AuditEvent::daemon_stopped());
        let _ = self.flush();
    }
}
