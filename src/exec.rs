//! Connecting to Postgres and running a checked plan.
//!
//! Layer two of the read-only guarantee lives here: every statement runs inside
//! `BEGIN TRANSACTION READ ONLY`, and the transaction is rolled back on every
//! path out of this module unless the caller explicitly asked to commit *and*
//! the policy allows writes. Postgres itself rejects writes inside a read-only
//! transaction, so even a statement that slips past the parser cannot change
//! anything.

use crate::config::{Connection, Mode, Policy};
use crate::output::ResultSet;
use crate::policy::{Kind, Plan};
use anyhow::{Context, Result, bail};
use native_tls::{Certificate, TlsConnector};
use postgres_native_tls::MakeTlsConnector;
use tokio_postgres::config::SslMode;
use tokio_postgres::{Client, NoTls, SimpleQueryMessage};

pub struct RunOptions {
    /// 0 = unlimited.
    pub max_rows: usize,
    /// Commit instead of rolling back. Ignored in read-only mode.
    pub commit: bool,
}

pub struct RunOutcome {
    pub sets: Vec<ResultSet>,
    pub committed: bool,
}

/// Open a connection. Panics are impossible here; every failure is an Err with
/// a message that says what to check.
pub async fn connect(conn: &Connection, password: Option<String>) -> Result<Client> {
    let mut cfg = tokio_postgres::Config::new();
    cfg.host(&conn.host)
        .port(conn.port)
        .dbname(&conn.database)
        .user(&conn.user)
        .application_name("psqlx")
        .connect_timeout(conn.connect_timeout()?);
    if let Some(pw) = &password {
        cfg.password(pw);
    }

    let mode = conn.sslmode.trim().to_ascii_lowercase();
    let (ssl_mode, verify) = match mode.as_str() {
        "disable" => (SslMode::Disable, None),
        "allow" | "prefer" => (SslMode::Prefer, Some(false)),
        "require" => (SslMode::Require, Some(false)),
        "verify-ca" => (SslMode::Require, Some(true)),
        "verify-full" => (SslMode::Require, Some(true)),
        other => bail!(
            "unknown sslmode '{other}' \
             (want disable, prefer, require, verify-ca, or verify-full)"
        ),
    };
    cfg.ssl_mode(ssl_mode);

    let client = match verify {
        None => {
            let (client, connection) = cfg
                .connect(NoTls)
                .await
                .with_context(|| format!("connecting to {}:{}", conn.host, conn.port))?;
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("psqlx: connection closed: {e}");
                }
            });
            client
        }
        Some(verify_certs) => {
            let mut builder = TlsConnector::builder();
            if verify_certs {
                if let Some(path) = &conn.sslrootcert {
                    let pem = std::fs::read(expand_tilde(path))
                        .with_context(|| format!("reading sslrootcert {path}"))?;
                    builder.add_root_certificate(
                        Certificate::from_pem(&pem).context("parsing sslrootcert as PEM")?,
                    );
                }
                // verify-ca checks the chain but not the hostname; verify-full checks both.
                if mode == "verify-ca" {
                    builder.danger_accept_invalid_hostnames(true);
                }
            } else {
                builder.danger_accept_invalid_certs(true);
                builder.danger_accept_invalid_hostnames(true);
            }
            let connector = MakeTlsConnector::new(builder.build().context("building TLS connector")?);
            let (client, connection) = cfg
                .connect(connector)
                .await
                .with_context(|| format!("connecting to {}:{}", conn.host, conn.port))?;
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("psqlx: connection closed: {e}");
                }
            });
            client
        }
    };

    // Belt and braces: make the *session* read-only, not just the transaction.
    //
    // The parser already rejects COMMIT/END/ABORT/BEGIN, which is what would
    // otherwise let a script close our read-only transaction and continue in
    // autocommit read-write mode. This makes that class of escape harmless even
    // if a statement ever gets past the parser: every implicit transaction on
    // this connection is read-only too. Turning it back off needs SET or
    // set_config(), both of which the parser blocks.
    if conn.policy.mode == Mode::ReadOnly {
        client
            .simple_query("SET SESSION default_transaction_read_only = on")
            .await
            .map_err(pretty_pg_error)
            .context("pinning the session to read-only")?;
    }

    Ok(client)
}

/// Run a checked plan inside a guarded transaction.
pub async fn run(
    client: &Client,
    plan: &Plan,
    policy: &Policy,
    opts: &RunOptions,
) -> Result<RunOutcome> {
    let read_only = policy.mode == Mode::ReadOnly;
    let begin = if read_only {
        "BEGIN TRANSACTION READ ONLY"
    } else {
        "BEGIN"
    };
    client
        .simple_query(begin)
        .await
        .map_err(pretty_pg_error)
        .context("starting transaction")?;

    // Guard rails that apply to everything in this transaction.
    let guards = format!(
        "SET LOCAL statement_timeout = {}; \
         SET LOCAL lock_timeout = {}; \
         SET LOCAL idle_in_transaction_session_timeout = {};",
        policy.statement_timeout_ms()?,
        policy.lock_timeout_ms()?,
        policy.statement_timeout_ms()?.saturating_add(5_000),
    );
    if let Err(e) = client.simple_query(&guards).await {
        let _ = client.simple_query("ROLLBACK").await;
        return Err(pretty_pg_error(e)).context("applying statement guards");
    }

    let mut sets = Vec::with_capacity(plan.statements.len());
    for stmt in &plan.statements {
        let capped = opts.max_rows > 0 && stmt.wrappable;
        let sql = if capped {
            // Cap rows server-side. We ask for one extra so we can tell the
            // difference between "exactly max_rows" and "more were available".
            format!(
                "SELECT * FROM (\n{}\n) AS psqlx_result LIMIT {}",
                stmt.sql,
                opts.max_rows + 1
            )
        } else {
            stmt.sql.clone()
        };

        match exec_one(client, &sql, &stmt.sql, &stmt.verb).await {
            Ok(mut rs) => {
                if capped && rs.rows.len() > opts.max_rows {
                    rs.rows.truncate(opts.max_rows);
                    rs.truncated = true;
                } else if !capped && opts.max_rows > 0 && rs.rows.len() > opts.max_rows {
                    rs.rows.truncate(opts.max_rows);
                    rs.truncated = true;
                }
                sets.push(rs);
            }
            Err(e) => {
                let _ = client.simple_query("ROLLBACK").await;
                return Err(e);
            }
        }
    }

    // Commit only when the policy permits writes and the caller asked for it.
    let should_commit = opts.commit && !read_only;
    if should_commit {
        client
            .simple_query("COMMIT")
            .await
            .map_err(pretty_pg_error)
            .context("committing")?;
    } else {
        client
            .simple_query("ROLLBACK")
            .await
            .map_err(pretty_pg_error)
            .context("rolling back")?;
    }

    Ok(RunOutcome {
        sets,
        committed: should_commit && plan.has_writes(),
    })
}

async fn exec_one(client: &Client, sql: &str, display: &str, verb: &str) -> Result<ResultSet> {
    let msgs = client.simple_query(sql).await.map_err(pretty_pg_error)?;

    let mut rs = ResultSet {
        statement: display.to_string(),
        ..Default::default()
    };

    for msg in msgs {
        match msg {
            SimpleQueryMessage::RowDescription(cols) => {
                rs.columns = cols.iter().map(|c| c.name().to_string()).collect();
            }
            SimpleQueryMessage::Row(row) => {
                if rs.columns.is_empty() {
                    rs.columns = row.columns().iter().map(|c| c.name().to_string()).collect();
                }
                let mut values = Vec::with_capacity(rs.columns.len());
                for i in 0..rs.columns.len() {
                    values.push(row.get(i).map(|s| s.to_string()));
                }
                rs.rows.push(values);
            }
            SimpleQueryMessage::CommandComplete(n) => {
                if rs.columns.is_empty() {
                    rs.command = Some(format!("{} {}", verb.to_uppercase(), n));
                }
            }
            _ => {}
        }
    }

    Ok(rs)
}

/// Turn a tokio-postgres error into something a human (or an agent) can act on.
fn pretty_pg_error(e: tokio_postgres::Error) -> anyhow::Error {
    if let Some(db) = e.as_db_error() {
        let mut msg = format!("{}: {}", db.severity(), db.message());
        if let Some(d) = db.detail() {
            msg.push_str(&format!("\nDETAIL: {d}"));
        }
        if let Some(h) = db.hint() {
            msg.push_str(&format!("\nHINT: {h}"));
        }
        if let Some(p) = db.position() {
            msg.push_str(&format!("\nPOSITION: {p:?}"));
        }
        anyhow::anyhow!(msg)
    } else {
        anyhow::anyhow!(e)
    }
}

pub fn expand_tilde(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest).to_string_lossy().into_owned();
        }
    }
    p.to_string()
}

/// Human-readable summary of what the transaction did, for stderr.
pub fn transaction_note(policy: &Policy, outcome: &RunOutcome, plan: &Plan) -> String {
    match policy.mode {
        Mode::ReadOnly => "read-only transaction, rolled back".to_string(),
        _ => {
            let wrote = plan
                .statements
                .iter()
                .any(|s| matches!(s.kind, Kind::Write | Kind::Ddl));
            if outcome.committed {
                "committed".to_string()
            } else if wrote {
                "rolled back (pass --commit to keep these changes)".to_string()
            } else {
                "rolled back".to_string()
            }
        }
    }
}
