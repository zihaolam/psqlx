//! Append-only audit log at `~/.psqlx/audit.log` (JSON lines).
//!
//! Every query attempt is recorded, including the ones the policy rejected —
//! the denials are the interesting half when you are trying to see what an
//! agent tried to do.

use crate::config::ensure_base_dir;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

#[derive(Debug, Serialize, Deserialize)]
pub struct Entry {
    pub ts: String,
    pub connection: String,
    pub mode: String,
    pub verdict: &'static str,
    pub sql: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u128>,
    pub committed: bool,
}

impl Entry {
    pub fn new(connection: &str, mode: &str, sql: &str, verdict: &'static str) -> Entry {
        Entry {
            ts: chrono::Local::now().to_rfc3339(),
            connection: connection.to_string(),
            mode: mode.to_string(),
            verdict,
            sql: sql.to_string(),
            error: None,
            rows: None,
            duration_ms: None,
            committed: false,
        }
    }
}

pub fn record(entry: &Entry) -> Result<()> {
    let path = ensure_base_dir()?.join("audit.log");
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    writeln!(f, "{}", serde_json::to_string(entry)?)?;
    Ok(())
}

/// Best-effort logging: an audit failure must never mask the real result.
pub fn record_quietly(entry: &Entry) {
    if let Err(e) = record(entry) {
        eprintln!("psqlx: warning: could not write audit log: {e}");
    }
}

pub fn tail(n: usize) -> Result<Vec<String>> {
    let path = ensure_base_dir()?.join("audit.log");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(path)?;
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = lines.len().saturating_sub(n);
    Ok(lines[start..].iter().map(|s| s.to_string()).collect())
}
