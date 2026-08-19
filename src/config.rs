//! Config file handling: `~/.psqlx/config.toml`.
//!
//! The config never contains a password. Secrets live in the OS keychain, an
//! env var, or a shell command that fetches them on demand.

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

pub const APP_NAME: &str = "psqlx";

/// `$PSQLX_HOME`, else `~/.psqlx`.
pub fn base_dir() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("PSQLX_HOME") {
        if !p.is_empty() {
            return Ok(PathBuf::from(p));
        }
    }
    let home = dirs::home_dir().ok_or_else(|| anyhow!("cannot determine home directory"))?;
    Ok(home.join(".psqlx"))
}

pub fn ensure_base_dir() -> Result<PathBuf> {
    let dir = base_dir()?;
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    // Best effort: keep the whole tree owner-only.
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    Ok(dir)
}

pub fn config_path() -> Result<PathBuf> {
    Ok(base_dir()?.join("config.toml"))
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_connection: Option<String>,
    #[serde(default)]
    pub connections: BTreeMap<String, Connection>,
}

impl Config {
    pub fn load() -> Result<Config> {
        let path = config_path()?;
        if !path.exists() {
            return Ok(Config::default());
        }
        let text = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self) -> Result<()> {
        ensure_base_dir()?;
        let path = config_path()?;
        let text = toml::to_string_pretty(self).context("serializing config")?;
        let tmp = path.with_extension("toml.tmp");
        fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        fs::rename(&tmp, &path).with_context(|| format!("installing {}", path.display()))?;
        Ok(())
    }

    /// Resolve a connection by name, falling back to `default_connection`.
    pub fn resolve<'a>(&'a self, name: Option<&str>) -> Result<(String, &'a Connection)> {
        let name = match name {
            Some(n) => n.to_string(),
            None => self.default_connection.clone().ok_or_else(|| {
                anyhow!("no connection given and no default is set (run `psqlx conn default <name>`)")
            })?,
        };
        let conn = self.connections.get(&name).ok_or_else(|| {
            let known: Vec<_> = self.connections.keys().cloned().collect();
            if known.is_empty() {
                anyhow!("unknown connection '{name}'; no connections configured yet (run `psqlx conn add <name>`)")
            } else {
                anyhow!("unknown connection '{name}'; known: {}", known.join(", "))
            }
        })?;
        Ok((name, conn))
    }
}

fn default_port() -> u16 {
    5432
}
fn default_sslmode() -> String {
    "prefer".into()
}
fn default_connect_timeout() -> String {
    "10s".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Postgres host as reachable from this machine. If you run your own SSH
    /// tunnel, point this at the local end of it (e.g. 127.0.0.1).
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub database: String,
    pub user: String,
    #[serde(default)]
    pub password: PasswordSource,
    /// disable | prefer | require | verify-ca | verify-full
    #[serde(default = "default_sslmode")]
    pub sslmode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sslrootcert: Option<String>,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout: String,
    #[serde(default)]
    pub policy: Policy,
}

impl Connection {
    pub fn connect_timeout(&self) -> Result<Duration> {
        parse_duration(&self.connect_timeout).context("connect_timeout")
    }

    /// One-line summary, safe to print (never contains a secret).
    pub fn summary(&self) -> String {
        format!("{}@{}:{}/{}", self.user, self.host, self.port, self.database)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "kebab-case")]
pub enum PasswordSource {
    /// No password (peer/trust auth, or a .pgpass on the tunnel host).
    None,
    /// OS keychain, under service `psqlx`, account = connection name.
    Keyring,
    /// Read from an environment variable at query time.
    Env { var: String },
    /// Run a shell command and use its stdout (e.g. `op read op://...`).
    Command { command: String },
}

impl Default for PasswordSource {
    fn default() -> Self {
        PasswordSource::None
    }
}

impl PasswordSource {
    pub fn label(&self) -> String {
        match self {
            PasswordSource::None => "none".into(),
            PasswordSource::Keyring => "keychain".into(),
            PasswordSource::Env { var } => format!("env:{var}"),
            PasswordSource::Command { .. } => "command".into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// SELECT-family only, run inside `BEGIN TRANSACTION READ ONLY` and always
    /// rolled back. The default.
    ReadOnly,
    /// Additionally allows INSERT/UPDATE/DELETE (optionally restricted to
    /// `allow_write_tables`). Still no DDL. Commits only with `--commit`.
    ReadWrite,
    /// Anything goes, including DDL. Commits only with `--commit`.
    Unrestricted,
}

impl Default for Mode {
    fn default() -> Self {
        Mode::ReadOnly
    }
}

impl Mode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::ReadOnly => "read-only",
            Mode::ReadWrite => "read-write",
            Mode::Unrestricted => "unrestricted",
        }
    }

    pub fn parse(s: &str) -> Result<Mode> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "read-only" | "readonly" | "ro" => Ok(Mode::ReadOnly),
            "read-write" | "readwrite" | "rw" => Ok(Mode::ReadWrite),
            "unrestricted" | "all" => Ok(Mode::Unrestricted),
            other => bail!("unknown mode '{other}' (want read-only, read-write, or unrestricted)"),
        }
    }
}

fn default_max_rows() -> usize {
    1000
}
fn default_statement_timeout() -> String {
    "30s".into()
}
fn default_lock_timeout() -> String {
    "5s".into()
}
fn default_max_statements() -> usize {
    20
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub mode: Mode,
    /// Hard cap on rows returned per statement. 0 = unlimited.
    #[serde(default = "default_max_rows")]
    pub max_rows: usize,
    #[serde(default = "default_statement_timeout")]
    pub statement_timeout: String,
    #[serde(default = "default_lock_timeout")]
    pub lock_timeout: String,
    /// Max statements in a single `psqlx query` call. 0 = unlimited.
    #[serde(default = "default_max_statements")]
    pub max_statements: usize,
    /// Reject any query that references these identifiers (table, view or
    /// column names), matched case-insensitively anywhere in the statement.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_tables: Vec<String>,
    /// In read-write mode, restrict writes to these tables. Empty = any table.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_write_tables: Vec<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            mode: Mode::default(),
            max_rows: default_max_rows(),
            statement_timeout: default_statement_timeout(),
            lock_timeout: default_lock_timeout(),
            max_statements: default_max_statements(),
            deny_tables: Vec::new(),
            allow_write_tables: Vec::new(),
        }
    }
}

impl Policy {
    pub fn statement_timeout_ms(&self) -> Result<u64> {
        Ok(parse_duration(&self.statement_timeout)
            .context("statement_timeout")?
            .as_millis() as u64)
    }
    pub fn lock_timeout_ms(&self) -> Result<u64> {
        Ok(parse_duration(&self.lock_timeout)
            .context("lock_timeout")?
            .as_millis() as u64)
    }
}

/// Parse `30s`, `500ms`, `5m`, `1h`, or a bare number (seconds).
pub fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        bail!("empty duration");
    }
    let split = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: f64 = num
        .parse()
        .with_context(|| format!("invalid duration '{s}'"))?;
    let mult = match unit.trim() {
        "" | "s" | "sec" | "secs" => 1000.0,
        "ms" => 1.0,
        "m" | "min" | "mins" => 60_000.0,
        "h" | "hr" | "hrs" => 3_600_000.0,
        other => bail!("unknown duration unit '{other}' in '{s}'"),
    };
    Ok(Duration::from_millis((n * mult).round() as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("10").unwrap(), Duration::from_secs(10));
        assert!(parse_duration("bogus").is_err());
    }

    #[test]
    fn default_policy_is_read_only() {
        assert_eq!(Policy::default().mode, Mode::ReadOnly);
    }
}
