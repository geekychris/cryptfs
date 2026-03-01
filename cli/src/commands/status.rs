// SPDX-License-Identifier: GPL-2.0
//! Status command.

use std::path::Path;

use anyhow::Result;

use super::{daemon_request, print_response};

pub async fn status(socket: &Path, json_output: bool) -> Result<()> {
    let resp = daemon_request(socket, serde_json::json!({
        "command": "status",
    })).await?;

    if !json_output && resp.success {
        if let Some(ref data) = resp.data {
            println!("CryptoFS Status");
            println!("{}", "=".repeat(40));
            println!(
                "Daemon version: {}",
                data.get("version").and_then(|v| v.as_str()).unwrap_or("?")
            );
            println!(
                "Daemon PID:     {}",
                data.get("pid").and_then(|v| v.as_u64()).unwrap_or(0)
            );
            println!(
                "Key provider:   {}",
                data.get("provider").and_then(|v| v.as_str()).unwrap_or("?")
            );
            println!(
                "Keys stored:    {}",
                data.get("key_count").and_then(|v| v.as_u64()).unwrap_or(0)
            );

            // Check if kernel module is loaded
            let module_loaded = std::fs::read_to_string("/proc/filesystems")
                .map(|s| s.contains("cryptofs"))
                .unwrap_or(false);
            println!(
                "Kernel module:  {}",
                if module_loaded { "loaded" } else { "not loaded" }
            );

            // Check for active mounts
            let mounts = std::fs::read_to_string("/proc/mounts")
                .unwrap_or_default();
            let cryptofs_mounts: Vec<&str> = mounts
                .lines()
                .filter(|l| l.contains("cryptofs"))
                .collect();
            if cryptofs_mounts.is_empty() {
                println!("Active mounts:  none");
            } else {
                println!("Active mounts:  {}", cryptofs_mounts.len());
                for mount in &cryptofs_mounts {
                    let parts: Vec<&str> = mount.split_whitespace().collect();
                    if parts.len() >= 2 {
                        println!("  {} -> {}", parts[0], parts[1]);
                    }
                }
            }

            return Ok(());
        }
    }

    print_response(&resp, json_output);
    Ok(())
}
