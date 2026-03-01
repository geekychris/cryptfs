// SPDX-License-Identifier: GPL-2.0
//! CryptoFS Key Management Daemon
//!
//! Manages encryption keys for the CryptoFS kernel module.
//! Provides a Unix domain socket API for the admin CLI and
//! injects keys into the Linux kernel keyring for the kernel module.

mod api;
mod audit;
mod keyring;
mod keystore;
mod provider;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::sync::RwLock;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::audit::AuditLog;
use crate::keystore::KeyStore;
use crate::provider::{KeyProvider, LocalKeyProvider};

/// Default paths
const DEFAULT_SOCKET_PATH: &str = "/var/run/cryptofs/keyd.sock";
const DEFAULT_KEY_DIR: &str = "/var/lib/cryptofs/keys";
const DEFAULT_AUDIT_LOG: &str = "/var/log/cryptofs/keyd.log";
const DEFAULT_PID_FILE: &str = "/var/run/cryptofs/keyd.pid";

#[derive(Parser, Debug)]
#[command(name = "cryptofs-keyd", about = "CryptoFS Key Management Daemon")]
struct Args {
    /// Path to the Unix domain socket
    #[arg(long, default_value = DEFAULT_SOCKET_PATH)]
    socket: PathBuf,

    /// Directory for encrypted key storage
    #[arg(long, default_value = DEFAULT_KEY_DIR)]
    key_dir: PathBuf,

    /// Path to audit log file
    #[arg(long, default_value = DEFAULT_AUDIT_LOG)]
    audit_log: PathBuf,

    /// Path to PID file
    #[arg(long, default_value = DEFAULT_PID_FILE)]
    pid_file: PathBuf,

    /// Run in foreground (don't daemonize)
    #[arg(long, short)]
    foreground: bool,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,
}

/// Shared daemon state accessible by API handlers
pub struct DaemonState {
    pub keystore: KeyStore,
    pub provider: Box<dyn KeyProvider>,
    pub audit: AuditLog,
}

impl DaemonState {
    fn new(key_dir: PathBuf, audit_log: PathBuf) -> Result<Self> {
        let keystore = KeyStore::new(&key_dir)
            .context("Failed to initialize key store")?;

        let provider = Box::new(LocalKeyProvider::new(key_dir.clone()));

        let audit = AuditLog::new(&audit_log)
            .context("Failed to initialize audit log")?;

        Ok(Self {
            keystore,
            provider,
            audit,
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize tracing
    let filter = EnvFilter::try_new(&args.log_level)
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(true)
        .init();

    info!("CryptoFS Key Management Daemon v{}", env!("CARGO_PKG_VERSION"));

    // Ensure directories exist
    ensure_dir(&args.key_dir)?;
    ensure_dir(args.socket.parent().unwrap_or(&PathBuf::from("/var/run/cryptofs")))?;
    ensure_dir(args.audit_log.parent().unwrap_or(&PathBuf::from("/var/log/cryptofs")))?;

    // Write PID file
    let pid = std::process::id();
    if let Some(parent) = args.pid_file.parent() {
        ensure_dir(parent)?;
    }
    std::fs::write(&args.pid_file, pid.to_string())
        .context("Failed to write PID file")?;
    info!("PID {} written to {}", pid, args.pid_file.display());

    // Initialize state
    let state = Arc::new(RwLock::new(
        DaemonState::new(args.key_dir.clone(), args.audit_log.clone())?
    ));

    info!("Key directory: {}", args.key_dir.display());
    info!("Socket path: {}", args.socket.display());
    info!("Audit log: {}", args.audit_log.display());

    // Clean up stale socket
    if args.socket.exists() {
        warn!("Removing stale socket at {}", args.socket.display());
        std::fs::remove_file(&args.socket)?;
    }

    // Set up signal handling for graceful shutdown
    let state_clone = state.clone();
    let socket_path = args.socket.clone();
    let pid_file = args.pid_file.clone();

    tokio::spawn(async move {
        let mut sigterm = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate()
        ).expect("Failed to register SIGTERM handler");

        let mut sigint = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::interrupt()
        ).expect("Failed to register SIGINT handler");

        tokio::select! {
            _ = sigterm.recv() => info!("Received SIGTERM"),
            _ = sigint.recv() => info!("Received SIGINT"),
        }

        info!("Shutting down...");

        // Cleanup
        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_file(&pid_file);

        // Flush audit log
        let state = state_clone.read().await;
        if let Err(e) = state.audit.flush() {
            warn!("Failed to flush audit log on shutdown: {}", e);
        }

        std::process::exit(0);
    });

    // Start the Unix socket API server
    info!("Starting API server on {}", args.socket.display());
    api::serve(args.socket, state).await?;

    Ok(())
}

fn ensure_dir(path: &std::path::Path) -> Result<()> {
    if !path.exists() {
        std::fs::create_dir_all(path)
            .with_context(|| format!("Failed to create directory: {}", path.display()))?;
    }
    Ok(())
}
