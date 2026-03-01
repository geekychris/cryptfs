// SPDX-License-Identifier: GPL-2.0

pub mod audit;
pub mod key;
pub mod mount;
pub mod policy;
pub mod status;

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// API response from daemon
#[derive(Debug, Deserialize)]
pub struct ApiResponse {
    pub success: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
}

/// Send a JSON request to the daemon and return the response.
pub async fn daemon_request(socket: &Path, request: serde_json::Value) -> Result<ApiResponse> {
    let stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!(
            "Cannot connect to daemon at {}. Is cryptofs-keyd running?",
            socket.display()
        ))?;

    let (reader, mut writer) = stream.into_split();

    let mut req_json = serde_json::to_string(&request)?;
    req_json.push('\n');
    writer.write_all(req_json.as_bytes()).await?;
    writer.flush().await?;

    let mut buf_reader = BufReader::new(reader);
    let mut response_line = String::new();
    buf_reader.read_line(&mut response_line).await?;

    let response: ApiResponse = serde_json::from_str(&response_line)
        .context("Invalid response from daemon")?;

    Ok(response)
}

/// Print a response - either as JSON or human-readable text.
pub fn print_response(response: &ApiResponse, json_output: bool) {
    if json_output {
        if let Ok(json) = serde_json::to_string_pretty(&serde_json::json!({
            "success": response.success,
            "data": response.data,
            "error": response.error,
        })) {
            println!("{}", json);
        }
    } else if response.success {
        if let Some(ref data) = response.data {
            if let Ok(pretty) = serde_json::to_string_pretty(data) {
                println!("{}", pretty);
            }
        } else {
            println!("OK");
        }
    } else if let Some(ref err) = response.error {
        eprintln!("Error: {}", err);
    }
}
