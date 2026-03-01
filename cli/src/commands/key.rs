// SPDX-License-Identifier: GPL-2.0
//! Key management commands.

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

use super::{daemon_request, print_response};

/// Prompt for a passphrase (without echo).
fn prompt_passphrase(prompt: &str) -> Result<String> {
    eprint!("{}: ", prompt);
    let mut passphrase = String::new();
    std::io::stdin().read_line(&mut passphrase)?;
    let passphrase = passphrase.trim().to_string();
    if passphrase.is_empty() {
        bail!("Passphrase cannot be empty");
    }
    Ok(passphrase)
}

pub async fn generate(socket: &Path, label: &str, json_output: bool) -> Result<()> {
    let passphrase = prompt_passphrase("Enter passphrase for new key")?;
    let confirm = prompt_passphrase("Confirm passphrase")?;
    if passphrase != confirm {
        bail!("Passphrases do not match");
    }

    let resp = daemon_request(socket, serde_json::json!({
        "command": "key_generate",
        "label": label,
        "passphrase": passphrase,
    })).await?;

    if !json_output && resp.success {
        if let Some(ref data) = resp.data {
            if let Some(key_id) = data.get("key_id").and_then(|v| v.as_str()) {
                println!("Generated key: {}", key_id);
                return Ok(());
            }
        }
    }
    print_response(&resp, json_output);
    Ok(())
}

pub async fn unlock(socket: &Path, key_id: &str, json_output: bool) -> Result<()> {
    let passphrase = prompt_passphrase("Enter passphrase")?;

    let resp = daemon_request(socket, serde_json::json!({
        "command": "key_unlock",
        "key_id": key_id,
        "passphrase": passphrase,
    })).await?;

    if !json_output && resp.success {
        println!("Key {} unlocked", key_id);
        return Ok(());
    }
    print_response(&resp, json_output);
    Ok(())
}

pub async fn lock(socket: &Path, key_id: &str, json_output: bool) -> Result<()> {
    let resp = daemon_request(socket, serde_json::json!({
        "command": "key_lock",
        "key_id": key_id,
    })).await?;

    if !json_output && resp.success {
        println!("Key {} locked", key_id);
        return Ok(());
    }
    print_response(&resp, json_output);
    Ok(())
}

pub async fn activate(socket: &Path, key_id: &str, json_output: bool) -> Result<()> {
    let resp = daemon_request(socket, serde_json::json!({
        "command": "key_activate",
        "key_id": key_id,
    })).await?;

    if !json_output && resp.success {
        if let Some(ref data) = resp.data {
            let serial = data.get("serial").and_then(|v| v.as_i64()).unwrap_or(0);
            println!("Key {} activated (keyring serial={})", key_id, serial);
            return Ok(());
        }
    }
    print_response(&resp, json_output);
    Ok(())
}

pub async fn deactivate(
    socket: &Path,
    key_id: &str,
    serial: i32,
    json_output: bool,
) -> Result<()> {
    let resp = daemon_request(socket, serde_json::json!({
        "command": "key_deactivate",
        "key_id": key_id,
        "serial": serial,
    })).await?;

    if !json_output && resp.success {
        println!("Key {} deactivated", key_id);
        return Ok(());
    }
    print_response(&resp, json_output);
    Ok(())
}

pub async fn rotate(socket: &Path, key_id: &str, json_output: bool) -> Result<()> {
    let passphrase = prompt_passphrase("Enter passphrase")?;

    let resp = daemon_request(socket, serde_json::json!({
        "command": "key_rotate",
        "key_id": key_id,
        "passphrase": passphrase,
    })).await?;

    if !json_output && resp.success {
        if let Some(ref data) = resp.data {
            let version = data.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
            println!("Key {} rotated to version {}", key_id, version);
            return Ok(());
        }
    }
    print_response(&resp, json_output);
    Ok(())
}

pub async fn import(
    socket: &Path,
    label: &str,
    file: Option<PathBuf>,
    hex: Option<String>,
    json_output: bool,
) -> Result<()> {
    let key_hex = if let Some(hex_str) = hex {
        hex_str
    } else if let Some(path) = file {
        std::fs::read_to_string(&path)?
            .trim()
            .to_string()
    } else {
        bail!("Must provide either --hex or --file");
    };

    let passphrase = prompt_passphrase("Enter passphrase for imported key")?;

    let resp = daemon_request(socket, serde_json::json!({
        "command": "key_import",
        "label": label,
        "passphrase": passphrase,
        "key_hex": key_hex,
    })).await?;

    if !json_output && resp.success {
        if let Some(ref data) = resp.data {
            if let Some(key_id) = data.get("key_id").and_then(|v| v.as_str()) {
                println!("Imported key: {}", key_id);
                return Ok(());
            }
        }
    }
    print_response(&resp, json_output);
    Ok(())
}

pub async fn delete(socket: &Path, key_id: &str, json_output: bool) -> Result<()> {
    // Confirm deletion
    eprint!("Delete key {}? This cannot be undone. [y/N]: ", key_id);
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if !input.trim().eq_ignore_ascii_case("y") {
        println!("Cancelled");
        return Ok(());
    }

    let resp = daemon_request(socket, serde_json::json!({
        "command": "key_delete",
        "key_id": key_id,
    })).await?;

    if !json_output && resp.success {
        println!("Key {} deleted", key_id);
        return Ok(());
    }
    print_response(&resp, json_output);
    Ok(())
}

pub async fn list(socket: &Path, json_output: bool) -> Result<()> {
    let resp = daemon_request(socket, serde_json::json!({
        "command": "key_list",
    })).await?;

    if !json_output && resp.success {
        if let Some(ref data) = resp.data {
            if let Some(keys) = data.get("keys").and_then(|v| v.as_array()) {
                if keys.is_empty() {
                    println!("No keys found");
                } else {
                    println!("{:<38} {:<20} {:<8} {:<8}", "KEY ID", "LABEL", "VERSION", "ACTIVE");
                    println!("{}", "-".repeat(76));
                    for key in keys {
                        println!(
                            "{:<38} {:<20} {:<8} {:<8}",
                            key.get("key_id").and_then(|v| v.as_str()).unwrap_or("?"),
                            key.get("label").and_then(|v| v.as_str()).unwrap_or("?"),
                            key.get("version").and_then(|v| v.as_u64()).unwrap_or(0),
                            key.get("active").and_then(|v| v.as_bool()).unwrap_or(false),
                        );
                    }
                }
                return Ok(());
            }
        }
    }
    print_response(&resp, json_output);
    Ok(())
}

pub async fn info(socket: &Path, key_id: &str, json_output: bool) -> Result<()> {
    let resp = daemon_request(socket, serde_json::json!({
        "command": "key_info",
        "key_id": key_id,
    })).await?;

    print_response(&resp, json_output);
    Ok(())
}
