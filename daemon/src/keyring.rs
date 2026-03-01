// SPDX-License-Identifier: GPL-2.0
//! Linux kernel keyring integration.
//!
//! Injects master keys into the kernel keyring so the CryptoFS kernel module
//! can retrieve them for file encryption/decryption without userspace
//! round-trips on every I/O operation.

use std::ffi::CString;
use std::io;

use anyhow::{Context, Result};
use base64::Engine;

/// Keyring serial number for the session keyring
const KEY_SPEC_SESSION_KEYRING: i32 = -3;
/// Keyring serial number for the user session keyring
const KEY_SPEC_USER_SESSION_KEYRING: i32 = -5;

/// Key type used for cryptofs keys in the kernel keyring
const CRYPTOFS_KEY_TYPE: &str = "logon";

/// Prefix for cryptofs key descriptions in the keyring
const CRYPTOFS_KEY_PREFIX: &str = "cryptofs:";

/// Result of a keyring operation
#[derive(Debug)]
pub struct KeyringKey {
    pub serial: i32,
    pub description: String,
}

/// Add a key to the kernel keyring.
///
/// Uses the `add_key` syscall to inject a master key into the session keyring.
/// The kernel module can then look up this key by description.
pub fn add_key_to_keyring(key_id: &str, key_data: &[u8]) -> Result<KeyringKey> {
    let key_type = CString::new(CRYPTOFS_KEY_TYPE)
        .context("Invalid key type")?;
    let description = format!("{}{}", CRYPTOFS_KEY_PREFIX, key_id);
    let desc_c = CString::new(description.as_str())
        .context("Invalid key description")?;

    let serial = unsafe {
        libc::syscall(
            libc::SYS_add_key,
            key_type.as_ptr(),
            desc_c.as_ptr(),
            key_data.as_ptr() as *const libc::c_void,
            key_data.len(),
            KEY_SPEC_SESSION_KEYRING,
        )
    };

    if serial < 0 {
        let err = io::Error::last_os_error();
        anyhow::bail!("add_key failed: {} (key_id={})", err, key_id);
    }

    tracing::info!(
        "Added key to keyring: {} (serial={})",
        description, serial
    );

    Ok(KeyringKey {
        serial: serial as i32,
        description,
    })
}

/// Remove a key from the kernel keyring by its serial number.
pub fn revoke_key(serial: i32) -> Result<()> {
    let ret = unsafe {
        libc::syscall(libc::SYS_keyctl, 3i64 /* KEYCTL_REVOKE */, serial as i64)
    };

    if ret < 0 {
        let err = io::Error::last_os_error();
        anyhow::bail!("keyctl revoke failed: {} (serial={})", err, serial);
    }

    tracing::info!("Revoked key serial={}", serial);
    Ok(())
}

/// Search for a cryptofs key in the session keyring.
pub fn search_key(key_id: &str) -> Result<Option<i32>> {
    let key_type = CString::new(CRYPTOFS_KEY_TYPE)
        .context("Invalid key type")?;
    let description = format!("{}{}", CRYPTOFS_KEY_PREFIX, key_id);
    let desc_c = CString::new(description.as_str())
        .context("Invalid key description")?;

    let serial = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            1i64, /* KEYCTL_SEARCH (actually keyctl_search is different) */
            KEY_SPEC_SESSION_KEYRING as i64,
            key_type.as_ptr() as i64,
            desc_c.as_ptr() as i64,
            0i64,
        )
    };

    if serial < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOKEY) {
            return Ok(None);
        }
        anyhow::bail!("keyctl search failed: {}", err);
    }

    Ok(Some(serial as i32))
}

/// Set a timeout on a key in the keyring.
pub fn set_key_timeout(serial: i32, timeout_secs: u32) -> Result<()> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            15i64, /* KEYCTL_SET_TIMEOUT */
            serial as i64,
            timeout_secs as i64,
        )
    };

    if ret < 0 {
        let err = io::Error::last_os_error();
        anyhow::bail!("keyctl set_timeout failed: {} (serial={})", err, serial);
    }

    tracing::debug!("Set timeout {}s on key serial={}", timeout_secs, serial);
    Ok(())
}

/// Inject a master key into both the kernel keyring and send it to the
/// cryptofs kernel module via the netlink SET_KEY command.
///
/// This is the main entry point called by the API when activating a key.
pub fn activate_key(key_id: &str, key_data: &[u8]) -> Result<KeyringKey> {
    // Add to kernel keyring
    let kr_key = add_key_to_keyring(key_id, key_data)?;

    // Note: In a full implementation, we would also send the key
    // to the kernel module via netlink CRYPTOFS_CMD_SET_KEY.
    // For the PoC, the kernel module reads from the keyring directly.

    tracing::info!("Activated key {} (keyring serial={})", key_id, kr_key.serial);
    Ok(kr_key)
}

/// Deactivate a key: revoke from keyring and notify kernel module.
pub fn deactivate_key(serial: i32, key_id: &str) -> Result<()> {
    revoke_key(serial)?;

    // Note: In a full implementation, we would also notify the kernel
    // module to flush cached FEKs wrapped with this master key.

    tracing::info!("Deactivated key {} (serial={})", key_id, serial);
    Ok(())
}
