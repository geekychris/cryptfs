// SPDX-License-Identifier: GPL-2.0
//! Policy management commands.
//!
//! Policies are managed via netlink communication with the kernel module.
//! For the PoC, we shell out to a helper or use a simplified approach.

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Result};

/// Add a policy rule.
///
/// Communicates with the kernel module via netlink to add an access policy.
/// For the PoC, this uses a helper script that sends the netlink message.
pub async fn add(dir: &Path, rule_type: &str, value: &str, perm: &str) -> Result<()> {
    // Validate rule type
    let type_id = match rule_type {
        "uid" => 0,
        "gid" => 1,
        "binary-path" => 2,
        "binary-hash" => 3,
        "process-name" => 4,
        _ => bail!(
            "Invalid policy type '{}'. Must be one of: uid, gid, binary-path, binary-hash, process-name",
            rule_type
        ),
    };

    // Validate permission
    let perm_id = match perm {
        "allow" => 1,
        "deny" => 0,
        _ => bail!("Invalid permission '{}'. Must be 'allow' or 'deny'", perm),
    };

    println!(
        "Adding policy: dir={} type={} value={} perm={}",
        dir.display(),
        rule_type,
        value,
        perm
    );

    // In a full implementation, this would use the genetlink library
    // to send CRYPTOFS_CMD_ADD_POLICY to the kernel module.
    // For the PoC, we document the expected netlink message format.
    //
    // Netlink message format:
    //   CRYPTOFS_ATTR_POLICY_DIR: string (directory path)
    //   CRYPTOFS_ATTR_POLICY_TYPE: u32 (type_id)
    //   CRYPTOFS_ATTR_POLICY_VALUE: string (match value)
    //   CRYPTOFS_ATTR_POLICY_PERM: u32 (perm_id)

    // For now, write to a policy file that the provision script can load
    let policy_dir = Path::new("/etc/cryptofs/policies");
    if !policy_dir.exists() {
        std::fs::create_dir_all(policy_dir)?;
    }

    let policy = serde_json::json!({
        "directory": dir.display().to_string(),
        "type": rule_type,
        "type_id": type_id,
        "value": value,
        "permission": perm,
        "perm_id": perm_id,
    });

    let policy_file = policy_dir.join(format!(
        "{}_{}.json",
        rule_type,
        value.replace('/', "_")
    ));
    std::fs::write(&policy_file, serde_json::to_string_pretty(&policy)?)?;

    println!("Policy saved to {}", policy_file.display());
    println!("Note: Use 'cryptofs-admin policy load' to apply to running kernel module");
    Ok(())
}

/// Remove a policy rule.
pub async fn remove(rule_id: &str) -> Result<()> {
    let policy_dir = Path::new("/etc/cryptofs/policies");
    let policy_file = policy_dir.join(format!("{}.json", rule_id));

    if policy_file.exists() {
        std::fs::remove_file(&policy_file)?;
        println!("Removed policy: {}", rule_id);
    } else {
        // Try to find by partial match
        let mut found = false;
        if policy_dir.exists() {
            for entry in std::fs::read_dir(policy_dir)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().to_string();
                if name.contains(rule_id) {
                    std::fs::remove_file(entry.path())?;
                    println!("Removed policy: {}", name);
                    found = true;
                }
            }
        }
        if !found {
            bail!("Policy not found: {}", rule_id);
        }
    }

    Ok(())
}

/// List active policies.
pub async fn list(dir: Option<&Path>) -> Result<()> {
    let policy_dir = Path::new("/etc/cryptofs/policies");

    if !policy_dir.exists() {
        println!("No policies configured");
        return Ok(());
    }

    println!(
        "{:<30} {:<15} {:<30} {:<10}",
        "DIRECTORY", "TYPE", "VALUE", "PERMISSION"
    );
    println!("{}", "-".repeat(87));

    let mut count = 0;
    for entry in std::fs::read_dir(policy_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map(|e| e == "json").unwrap_or(false) {
            let data = std::fs::read_to_string(&path)?;
            if let Ok(policy) = serde_json::from_str::<serde_json::Value>(&data) {
                let policy_dir_str = policy
                    .get("directory")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");

                // Filter by directory if specified
                if let Some(filter_dir) = dir {
                    if policy_dir_str != filter_dir.display().to_string() {
                        continue;
                    }
                }

                println!(
                    "{:<30} {:<15} {:<30} {:<10}",
                    policy_dir_str,
                    policy.get("type").and_then(|v| v.as_str()).unwrap_or("?"),
                    policy.get("value").and_then(|v| v.as_str()).unwrap_or("?"),
                    policy.get("permission").and_then(|v| v.as_str()).unwrap_or("?"),
                );
                count += 1;
            }
        }
    }

    if count == 0 {
        println!("No policies found");
    } else {
        println!("\n{} policy rule(s)", count);
    }

    Ok(())
}
