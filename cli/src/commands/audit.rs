// SPDX-License-Identifier: GPL-2.0
//! Audit log command.

use std::path::Path;

use anyhow::Result;

use super::{daemon_request, print_response};

pub async fn audit(
    socket: &Path,
    count: usize,
    _tail: bool,
    json_output: bool,
) -> Result<()> {
    let resp = daemon_request(socket, serde_json::json!({
        "command": "audit_list",
        "count": count,
    })).await?;

    if !json_output && resp.success {
        if let Some(ref data) = resp.data {
            if let Some(events) = data.get("events").and_then(|v| v.as_array()) {
                if events.is_empty() {
                    println!("No audit events");
                } else {
                    println!(
                        "{:<28} {:<20} {:<38} {}",
                        "TIMESTAMP", "EVENT", "KEY ID", "DETAILS"
                    );
                    println!("{}", "-".repeat(100));
                    for event in events {
                        println!(
                            "{:<28} {:<20} {:<38} {}",
                            event.get("timestamp").and_then(|v| v.as_str()).unwrap_or("?"),
                            event.get("event_type").and_then(|v| v.as_str()).unwrap_or("?"),
                            event.get("key_id").and_then(|v| v.as_str()).unwrap_or("-"),
                            event.get("details").and_then(|v| v.as_str()).unwrap_or(""),
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
