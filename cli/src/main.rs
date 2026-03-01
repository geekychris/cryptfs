// SPDX-License-Identifier: GPL-2.0
//! CryptoFS Administration CLI
//!
//! Provides command-line management of the CryptoFS filesystem,
//! communicating with the cryptofs-keyd daemon via Unix socket.

mod commands;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

/// Default daemon socket path
const DEFAULT_SOCKET: &str = "/var/run/cryptofs/keyd.sock";

#[derive(Parser)]
#[command(
    name = "cryptofs-admin",
    about = "CryptoFS Transparent Encryption Administration",
    version
)]
struct Cli {
    /// Path to daemon Unix socket
    #[arg(long, global = true, default_value = DEFAULT_SOCKET)]
    socket: PathBuf,

    /// Output format (text, json)
    #[arg(long, global = true, default_value = "text")]
    format: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Mount an encrypted filesystem
    Mount {
        /// Source directory (lower filesystem)
        source: PathBuf,
        /// Mount point
        mountpoint: PathBuf,
        /// Key ID to use for encryption
        #[arg(long)]
        key_id: Option<String>,
    },

    /// Unmount an encrypted filesystem
    Umount {
        /// Mount point to unmount
        mountpoint: PathBuf,
    },

    /// Key management commands
    Key {
        #[command(subcommand)]
        action: KeyCommands,
    },

    /// Access policy management
    Policy {
        #[command(subcommand)]
        action: PolicyCommands,
    },

    /// Show system status
    Status,

    /// View audit log
    Audit {
        /// Number of recent events to show
        #[arg(long, short, default_value = "20")]
        count: usize,

        /// Follow (tail) the audit log
        #[arg(long, short)]
        tail: bool,
    },
}

#[derive(Subcommand)]
enum KeyCommands {
    /// Generate a new master key
    Generate {
        /// Human-readable label for the key
        #[arg(long)]
        label: String,
    },

    /// Unlock a key (decrypt and load into memory)
    Unlock {
        /// Key ID to unlock
        key_id: String,
    },

    /// Lock a key (clear from memory)
    Lock {
        /// Key ID to lock
        key_id: String,
    },

    /// Activate a key (inject into kernel keyring)
    Activate {
        /// Key ID to activate
        key_id: String,
    },

    /// Deactivate a key (revoke from kernel keyring)
    Deactivate {
        /// Key ID to deactivate
        key_id: String,
        /// Kernel keyring serial number
        #[arg(long)]
        serial: i32,
    },

    /// Rotate a master key
    Rotate {
        /// Key ID to rotate
        key_id: String,
    },

    /// Import a key from hex or file
    Import {
        /// Label for the imported key
        #[arg(long)]
        label: String,
        /// Path to file containing hex-encoded key
        #[arg(long)]
        file: Option<PathBuf>,
        /// Hex-encoded key (alternative to --file)
        #[arg(long)]
        hex: Option<String>,
    },

    /// Delete a key
    Delete {
        /// Key ID to delete
        key_id: String,
    },

    /// List all keys
    List,

    /// Show detailed key info
    Info {
        /// Key ID
        key_id: String,
    },
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// Add an access policy rule
    Add {
        /// Directory to apply the policy to
        #[arg(long)]
        dir: PathBuf,

        /// Policy type: uid, gid, binary-path, binary-hash, process-name
        #[arg(long, rename_all = "kebab-case")]
        r#type: String,

        /// Value to match (UID number, path, hash, etc.)
        #[arg(long)]
        value: String,

        /// Permission: allow or deny
        #[arg(long, default_value = "allow")]
        perm: String,
    },

    /// Remove a policy rule
    Remove {
        /// Rule ID to remove
        rule_id: String,
    },

    /// List active policies
    List {
        /// Filter by directory
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let json_output = cli.format == "json";

    match cli.command {
        Commands::Mount { source, mountpoint, key_id } => {
            commands::mount::mount(&source, &mountpoint, key_id.as_deref()).await?;
        }

        Commands::Umount { mountpoint } => {
            commands::mount::umount(&mountpoint).await?;
        }

        Commands::Key { action } => {
            match action {
                KeyCommands::Generate { label } => {
                    commands::key::generate(&cli.socket, &label, json_output).await?;
                }
                KeyCommands::Unlock { key_id } => {
                    commands::key::unlock(&cli.socket, &key_id, json_output).await?;
                }
                KeyCommands::Lock { key_id } => {
                    commands::key::lock(&cli.socket, &key_id, json_output).await?;
                }
                KeyCommands::Activate { key_id } => {
                    commands::key::activate(&cli.socket, &key_id, json_output).await?;
                }
                KeyCommands::Deactivate { key_id, serial } => {
                    commands::key::deactivate(&cli.socket, &key_id, serial, json_output).await?;
                }
                KeyCommands::Rotate { key_id } => {
                    commands::key::rotate(&cli.socket, &key_id, json_output).await?;
                }
                KeyCommands::Import { label, file, hex } => {
                    commands::key::import(&cli.socket, &label, file, hex, json_output).await?;
                }
                KeyCommands::Delete { key_id } => {
                    commands::key::delete(&cli.socket, &key_id, json_output).await?;
                }
                KeyCommands::List => {
                    commands::key::list(&cli.socket, json_output).await?;
                }
                KeyCommands::Info { key_id } => {
                    commands::key::info(&cli.socket, &key_id, json_output).await?;
                }
            }
        }

        Commands::Policy { action } => {
            match action {
                PolicyCommands::Add { dir, r#type, value, perm } => {
                    commands::policy::add(&dir, &r#type, &value, &perm).await?;
                }
                PolicyCommands::Remove { rule_id } => {
                    commands::policy::remove(&rule_id).await?;
                }
                PolicyCommands::List { dir } => {
                    commands::policy::list(dir.as_deref()).await?;
                }
            }
        }

        Commands::Status => {
            commands::status::status(&cli.socket, json_output).await?;
        }

        Commands::Audit { count, tail } => {
            commands::audit::audit(&cli.socket, count, tail, json_output).await?;
        }
    }

    Ok(())
}
