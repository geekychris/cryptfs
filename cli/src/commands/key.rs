// SPDX-License-Identifier: GPL-2.0
//! Key management commands.

use std::path::{Path, PathBuf};

use std::ffi::CString;

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

/// Unlock a key and inject it into the caller's session keyring (guarded mode).
pub async fn session_unlock(
    socket: &Path,
    key_id: &str,
    timeout: Option<u32>,
    json_output: bool,
) -> Result<()> {
    let passphrase = prompt_passphrase("Enter passphrase")?;

    let resp = daemon_request(socket, serde_json::json!({
        "command": "session_unlock",
        "key_id": key_id,
        "passphrase": passphrase,
        "timeout": timeout.unwrap_or(0),
    })).await?;

    if resp.success {
        if let Some(ref data) = resp.data {
            let key_hex = data.get("key_hex").and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Missing key_hex in response"))?;
            let key_bytes = hex_decode(key_hex)?;
            let timeout_val = data
                .get("timeout")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;

            // Build keyring description matching kernel's "cryptofs:<hex key_id>"
            let key_id_hex: String = key_id.chars().filter(|c| *c != '-').collect();
            let desc = format!("cryptofs:{}", key_id_hex);

            let serial = add_key_to_session(&desc, &key_bytes)?;

            if timeout_val > 0 {
                set_key_timeout(serial, timeout_val)?;
            }

            if !json_output {
                println!("Session unlocked for key {} (serial={})", key_id, serial);
                return Ok(());
            }
        }
    }
    print_response(&resp, json_output);
    Ok(())
}

// ---- local keyring helpers (called in the CLI process) ----

fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    let hex = hex.trim();
    if hex.len() % 2 != 0 {
        bail!("Odd-length hex string");
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("Invalid hex at {}: {}", i, e))
        })
        .collect()
}

fn add_key_to_session(description: &str, key_data: &[u8]) -> Result<i32> {
    let key_type = CString::new("logon")?;
    let desc = CString::new(description)?;

    let serial = unsafe {
        libc::syscall(
            libc::SYS_add_key,
            key_type.as_ptr(),
            desc.as_ptr(),
            key_data.as_ptr() as *const libc::c_void,
            key_data.len(),
            -3i32, // KEY_SPEC_SESSION_KEYRING
        )
    };

    if serial < 0 {
        let err = std::io::Error::last_os_error();
        bail!("add_key syscall failed: {}", err);
    }
    Ok(serial as i32)
}

fn set_key_timeout(serial: i32, timeout_secs: u32) -> Result<()> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            15i64, // KEYCTL_SET_TIMEOUT
            serial as i64,
            timeout_secs as i64,
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        bail!("keyctl set_timeout failed: {}", err);
    }
    Ok(())
}
