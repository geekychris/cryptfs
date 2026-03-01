// SPDX-License-Identifier: GPL-2.0
//! Mount and unmount commands.

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

/// Mount a CryptoFS filesystem.
///
/// Uses `mount -t cryptofs` which requires the kernel module to be loaded.
pub async fn mount(source: &Path, mountpoint: &Path, key_id: Option<&str>) -> Result<()> {
    // Validate paths
    if !source.exists() {
        bail!("Source directory does not exist: {}", source.display());
    }
    if !mountpoint.exists() {
        std::fs::create_dir_all(mountpoint)
            .with_context(|| format!("Cannot create mount point: {}", mountpoint.display()))?;
    }

    // Build mount options
    let mut opts = Vec::new();
    if let Some(kid) = key_id {
        opts.push(format!("key_id={}", kid));
    }

    let opts_str = if opts.is_empty() {
        String::new()
    } else {
        opts.join(",")
    };

    // Execute mount
    let mut cmd = Command::new("mount");
    cmd.arg("-t").arg("cryptofs");

    if !opts_str.is_empty() {
        cmd.arg("-o").arg(&opts_str);
    }

    cmd.arg(source).arg(mountpoint);

    println!("Mounting cryptofs: {} -> {}", source.display(), mountpoint.display());

    let output = cmd.output()
        .context("Failed to execute mount command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Mount failed: {}", stderr.trim());
    }

    println!("Mounted successfully");
    Ok(())
}

/// Unmount a CryptoFS filesystem.
pub async fn umount(mountpoint: &Path) -> Result<()> {
    let output = Command::new("umount")
        .arg(mountpoint)
        .output()
        .context("Failed to execute umount command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Unmount failed: {}", stderr.trim());
    }

    println!("Unmounted {}", mountpoint.display());
    Ok(())
}
