//! Password resolution. Nothing here ever writes a secret to disk, and no
//! psqlx subcommand can print one back out.

use crate::config::{APP_NAME, PasswordSource};
use anyhow::{Context, Result, bail};
use std::process::Command;

fn entry(name: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(APP_NAME, name).context("opening keychain entry")
}

pub fn store(name: &str, password: &str) -> Result<()> {
    entry(name)?
        .set_password(password)
        .context("saving password to the keychain")
}

pub fn fetch(name: &str) -> Result<Option<String>> {
    match entry(name)?.get_password() {
        Ok(p) => Ok(Some(p)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e).context("reading password from the keychain"),
    }
}

pub fn delete(name: &str) -> Result<()> {
    match entry(name)?.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e).context("deleting password from the keychain"),
    }
}

/// Resolve the password for a connection, or `None` if it has no password.
pub fn resolve(name: &str, source: &PasswordSource) -> Result<Option<String>> {
    match source {
        PasswordSource::None => Ok(None),
        PasswordSource::Keyring => {
            let p = fetch(name)?;
            if p.is_none() {
                bail!(
                    "no password in the keychain for connection '{name}'.\n\
                     Run `psqlx conn set-password {name}` to store one."
                );
            }
            Ok(p)
        }
        PasswordSource::Env { var } => match std::env::var(var) {
            Ok(v) => Ok(Some(v)),
            Err(_) => bail!("connection '{name}' expects the password in ${var}, which is not set"),
        },
        PasswordSource::Command { command } => {
            let out = Command::new("sh")
                .arg("-c")
                .arg(command)
                .output()
                .with_context(|| format!("running password command for '{name}'"))?;
            if !out.status.success() {
                let err = String::from_utf8_lossy(&out.stderr);
                bail!(
                    "password command for '{name}' failed ({}): {}",
                    out.status,
                    err.trim()
                );
            }
            let pw = String::from_utf8_lossy(&out.stdout).trim_end_matches('\n').to_string();
            if pw.is_empty() {
                bail!("password command for '{name}' produced no output");
            }
            Ok(Some(pw))
        }
    }
}
