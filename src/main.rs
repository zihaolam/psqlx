//! psqlx — a policy-guarded Postgres CLI.
//!
//! You configure a named connection once. Agents then run
//! `psqlx query <name> "<sql>"` and never see a host, a user, or a password.
//! Every connection is read-only unless you deliberately say otherwise.

mod audit;
mod config;
mod exec;
mod introspect;
mod output;
mod policy;
mod secrets;
mod sqlparse;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use config::{Config, Connection, Mode, PasswordSource, Policy};
use output::Format;
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::time::Instant;

/// Exit code used when the policy rejects a statement, so callers can tell a
/// refusal apart from a connection failure or a SQL error.
const EXIT_POLICY_DENIED: i32 = 3;

#[derive(Parser)]
#[command(
    name = "psqlx",
    version,
    about = "Policy-guarded Postgres access for AI agents. Read-only by default.",
    long_about = "psqlx keeps database credentials out of an agent's reach.\n\n\
        You register a connection once (host, user, password) and the password goes to the OS \
        keychain. Agents then run `psqlx query <connection> \"<sql>\"`, which is checked against \
        a policy and executed inside a read-only transaction that is always rolled back.",
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Manage saved connections
    #[command(subcommand, visible_alias = "conn")]
    Connection(ConnCmd),

    /// Run SQL against a connection
    #[command(visible_alias = "q")]
    Query(QueryArgs),

    /// List tables and views
    Tables {
        /// Connection name (omit to use the default)
        connection: Option<String>,
        /// Restrict to one schema
        #[arg(long)]
        schema: Option<String>,
        #[arg(long, default_value = "table")]
        format: String,
    },

    /// Show columns, indexes and constraints for a table
    #[command(visible_alias = "d")]
    Describe {
        /// Connection name, then table. With one argument, the default
        /// connection is used and the argument is the table.
        arg1: String,
        arg2: Option<String>,
        #[arg(long, default_value = "table")]
        format: String,
    },

    /// List schemas
    Schemas {
        connection: Option<String>,
        #[arg(long, default_value = "table")]
        format: String,
    },

    /// Show or change a connection's policy
    #[command(subcommand)]
    Policy(PolicyCmd),

    /// Show the audit log
    Audit {
        /// How many entries to show
        #[arg(short = 'n', long, default_value_t = 20)]
        tail: usize,
    },

    /// Print the instructions to hand to an agent
    Guide,
}

#[derive(Subcommand)]
enum ConnCmd {
    /// Add a connection. Prompts for anything you leave out.
    Add(AddArgs),
    /// List connections (never prints secrets)
    #[command(visible_alias = "ls")]
    List,
    /// Show one connection's settings
    Show { name: String },
    /// Change fields on an existing connection
    Edit(EditArgs),
    /// Remove a connection and its stored password
    #[command(visible_alias = "remove")]
    Rm { name: String },
    /// Connect and report server, user and privileges
    Test { name: String },
    /// Set which connection is used when none is named
    Default { name: String },
    /// Store or replace the password in the OS keychain
    SetPassword { name: String },
}

#[derive(Args)]
struct AddArgs {
    /// Name agents will use, e.g. `prod`. Prompted for if omitted.
    name: Option<String>,

    /// Take everything from a connection URL: postgres://user:pass@host:port/db
    ///
    /// Careful: this puts the password in your shell history. Run
    /// `psqlx conn add <name>` with no flags to paste the URL at a hidden
    /// prompt instead.
    #[arg(long)]
    url: Option<String>,

    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    port: Option<u16>,
    /// Database name
    #[arg(long, visible_alias = "dbname")]
    db: Option<String>,
    #[arg(long)]
    user: Option<String>,
    #[arg(long)]
    description: Option<String>,

    /// disable | prefer | require | verify-ca | verify-full
    #[arg(long)]
    sslmode: Option<String>,
    /// CA certificate for verify-ca / verify-full
    #[arg(long)]
    sslrootcert: Option<String>,

    /// Read the password from stdin instead of prompting
    #[arg(long, conflicts_with_all = ["password_env", "password_command", "no_password"])]
    password_stdin: bool,
    /// Read the password from this environment variable at query time
    #[arg(long, value_name = "VAR", conflicts_with_all = ["password_command", "no_password"])]
    password_env: Option<String>,
    /// Run this shell command at query time and use its output as the password
    #[arg(long, value_name = "CMD", conflicts_with = "no_password")]
    password_command: Option<String>,
    /// This connection needs no password
    #[arg(long)]
    no_password: bool,

    /// Policy mode: read-only (default), read-write, or unrestricted
    #[arg(long, default_value = "read-only")]
    mode: String,

    /// Also make this the default connection
    #[arg(long)]
    set_default: bool,

    /// Skip the connection test after saving
    #[arg(long)]
    no_test: bool,
}

#[derive(Args)]
struct EditArgs {
    name: String,
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    port: Option<u16>,
    #[arg(long, visible_alias = "dbname")]
    db: Option<String>,
    #[arg(long)]
    user: Option<String>,
    #[arg(long)]
    description: Option<String>,
    #[arg(long)]
    sslmode: Option<String>,
    #[arg(long)]
    sslrootcert: Option<String>,
}

#[derive(Args)]
struct QueryArgs {
    /// Connection name, then SQL. With one argument, the default connection is
    /// used and the argument is the SQL.
    arg1: Option<String>,
    arg2: Option<String>,

    /// Read SQL from a file, or `-` for stdin
    #[arg(short = 'f', long, value_name = "FILE")]
    file: Option<PathBuf>,

    /// table | json | csv | markdown
    #[arg(long, default_value = "table")]
    format: String,

    /// Override the policy's row cap for this call (0 = no cap)
    #[arg(long, value_name = "N")]
    max_rows: Option<usize>,

    /// Override the policy's statement timeout, e.g. 5s, 500ms, 2m
    #[arg(long, value_name = "DURATION")]
    timeout: Option<String>,

    /// Commit instead of rolling back. Ignored on read-only connections.
    #[arg(long)]
    commit: bool,
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Print the effective policy
    Show { connection: Option<String> },
    /// Change policy settings
    Set(PolicySetArgs),
}

#[derive(Args)]
struct PolicySetArgs {
    connection: String,
    /// read-only | read-write | unrestricted
    #[arg(long)]
    mode: Option<String>,
    /// Row cap per statement (0 = unlimited)
    #[arg(long)]
    max_rows: Option<usize>,
    #[arg(long)]
    statement_timeout: Option<String>,
    #[arg(long)]
    lock_timeout: Option<String>,
    /// Max statements per query call (0 = unlimited)
    #[arg(long)]
    max_statements: Option<usize>,
    /// Reject queries referencing this identifier. Repeatable.
    #[arg(long = "deny-table", value_name = "NAME")]
    deny_tables: Vec<String>,
    /// Clear the deny_tables list
    #[arg(long)]
    clear_deny_tables: bool,
    /// In read-write mode, limit writes to this table. Repeatable.
    #[arg(long = "allow-write-table", value_name = "NAME")]
    allow_write_tables: Vec<String>,
    /// Clear the allow_write_tables list
    #[arg(long)]
    clear_allow_write_tables: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(e) = dispatch(cli).await {
        eprintln!("psqlx: {e:#}");
        std::process::exit(1);
    }
}

async fn dispatch(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Connection(c) => connection_cmd(c).await,
        Cmd::Query(a) => query_cmd(a).await,
        Cmd::Tables {
            connection,
            schema,
            format,
        } => {
            let (name, conn, client) = open(connection.as_deref()).await?;
            let sets = introspect::tables(&client, &conn.policy, schema.as_deref()).await?;
            emit(&sets, &format, &name, &conn, None)
        }
        Cmd::Describe { arg1, arg2, format } => {
            let (conn_name, table) = match arg2 {
                Some(t) => (Some(arg1), t),
                None => (None, arg1),
            };
            let (name, conn, client) = open(conn_name.as_deref()).await?;
            let sets = introspect::describe(&client, &conn.policy, &table).await?;
            emit(&sets, &format, &name, &conn, None)
        }
        Cmd::Schemas { connection, format } => {
            let (name, conn, client) = open(connection.as_deref()).await?;
            let sets = introspect::schemas(&client, &conn.policy).await?;
            emit(&sets, &format, &name, &conn, None)
        }
        Cmd::Policy(p) => policy_cmd(p),
        Cmd::Audit { tail } => {
            for line in audit::tail(tail)? {
                println!("{line}");
            }
            Ok(())
        }
        Cmd::Guide => {
            print!("{}", guide_text());
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// query
// ---------------------------------------------------------------------------

async fn query_cmd(args: QueryArgs) -> Result<()> {
    let cfg = Config::load()?;

    // `psqlx query prod "select 1"` vs `psqlx query "select 1"`.
    let (conn_name, sql_arg) = match (&args.arg1, &args.arg2) {
        (Some(a), Some(b)) => (Some(a.clone()), Some(b.clone())),
        (Some(a), None) => {
            if args.file.is_some() {
                (Some(a.clone()), None)
            } else if cfg.connections.contains_key(a) && !looks_like_sql(a) {
                bail!(
                    "'{a}' is a connection name but no SQL was given.\n\
                     Usage: psqlx query {a} \"select 1\""
                );
            } else {
                (None, Some(a.clone()))
            }
        }
        (None, _) => (None, None),
    };

    let sql = read_sql(sql_arg, args.file.as_ref())?;
    if sql.trim().is_empty() {
        bail!("no SQL given");
    }

    let (name, conn) = cfg.resolve(conn_name.as_deref().or(env_default().as_deref()))?;

    // Per-call overrides. Mode is deliberately not overridable from the CLI.
    let mut policy = conn.policy.clone();
    if let Some(n) = args.max_rows {
        policy.max_rows = n;
    }
    if let Some(t) = &args.timeout {
        config::parse_duration(t).with_context(|| format!("invalid --timeout '{t}'"))?;
        policy.statement_timeout = t.clone();
    }

    // --- layer 1: parse and check -------------------------------------
    let checked = sqlparse::split(&sql).and_then(|stmts| policy::evaluate(&stmts, &policy));
    let plan = match checked {
        Ok(p) => p,
        Err(e) => {
            let mut entry = audit::Entry::new(&name, policy.mode.as_str(), &sql, "denied");
            entry.error = Some(format!("{e:#}"));
            audit::record_quietly(&entry);
            eprintln!("psqlx: {e:#}");
            std::process::exit(EXIT_POLICY_DENIED);
        }
    };

    if args.commit && policy.mode == Mode::ReadOnly {
        bail!(
            "--commit is meaningless on a read-only connection.\n\
             Run `psqlx policy set {name} --mode read-write` first if that is really what you want."
        );
    }

    // Fail fast on a bad --format before we bother connecting.
    Format::parse(&args.format)?;
    let started = Instant::now();

    let password = secrets::resolve(&name, &conn.password)?;
    let client = exec::connect(conn, password).await?;

    let opts = exec::RunOptions {
        max_rows: policy.max_rows,
        commit: args.commit,
    };

    let outcome = match exec::run(&client, &plan, &policy, &opts).await {
        Ok(o) => o,
        Err(e) => {
            let mut entry = audit::Entry::new(&name, policy.mode.as_str(), &sql, "error");
            entry.error = Some(format!("{e:#}"));
            entry.duration_ms = Some(started.elapsed().as_millis());
            audit::record_quietly(&entry);
            return Err(e);
        }
    };

    let rows: usize = outcome.sets.iter().map(|s| s.row_count()).sum();
    let mut entry = audit::Entry::new(&name, policy.mode.as_str(), &sql, "allowed");
    entry.rows = Some(rows);
    entry.duration_ms = Some(started.elapsed().as_millis());
    entry.committed = outcome.committed;
    audit::record_quietly(&entry);

    let note = exec::transaction_note(&policy, &outcome, &plan);
    emit(&outcome.sets, &args.format, &name, conn, Some(&note))
}

/// Heuristic for the one-positional case: does this look like SQL rather than a
/// connection name? Connection names are single identifiers.
fn looks_like_sql(s: &str) -> bool {
    s.contains(char::is_whitespace) || s.contains('*') || s.contains(';')
}

fn env_default() -> Option<String> {
    std::env::var("PSQLX_CONNECTION").ok().filter(|s| !s.is_empty())
}

fn read_sql(sql: Option<String>, file: Option<&PathBuf>) -> Result<String> {
    match (sql, file) {
        (_, Some(path)) => {
            if path.as_os_str() == "-" {
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf)?;
                Ok(buf)
            } else {
                std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
            }
        }
        (Some(s), None) => Ok(s),
        (None, None) => bail!("no SQL given; pass it as an argument or use -f <file>"),
    }
}

/// Open a connection for the read-only introspection commands.
async fn open(name: Option<&str>) -> Result<(String, Connection, tokio_postgres::Client)> {
    let cfg = Config::load()?;
    let (name, conn) = cfg.resolve(name.or(env_default().as_deref()))?;
    let conn = conn.clone();
    let password = secrets::resolve(&name, &conn.password)?;
    let client = exec::connect(&conn, password).await?;
    Ok((name, conn, client))
}

fn emit(
    sets: &[output::ResultSet],
    format: &str,
    name: &str,
    conn: &Connection,
    note: Option<&str>,
) -> Result<()> {
    let format = Format::parse(format)?;
    let text = output::render(sets, format)?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(text.as_bytes())?;
    stdout.flush()?;

    // Diagnostics go to stderr so stdout stays parseable.
    if let Some(note) = note {
        eprintln!("-- psqlx: {name} [{}] {note}", conn.policy.mode.as_str());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// connections
// ---------------------------------------------------------------------------

async fn connection_cmd(cmd: ConnCmd) -> Result<()> {
    match cmd {
        ConnCmd::Add(args) => conn_add(args).await,
        ConnCmd::List => conn_list(),
        ConnCmd::Show { name } => conn_show(&name),
        ConnCmd::Edit(args) => conn_edit(args),
        ConnCmd::Rm { name } => conn_rm(&name),
        ConnCmd::Default { name } => conn_default(&name),
        ConnCmd::SetPassword { name } => conn_set_password(&name),
        ConnCmd::Test { name } => conn_test(&name).await,
    }
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        bail!("connection name must be non-empty and use only letters, digits, '-', '_' or '.'");
    }
    Ok(())
}

async fn conn_add(args: AddArgs) -> Result<()> {
    let interactive = std::io::stdin().is_terminal();
    let mut cfg = Config::load()?;

    // --- name ----------------------------------------------------------
    let name = match args.name.clone() {
        Some(n) => n,
        None if interactive => prompt("Connection name", None)?,
        None => bail!("a connection name is required"),
    };
    validate_name(&name)?;
    if cfg.connections.contains_key(&name) {
        bail!("connection '{name}' already exists (use `psqlx conn edit` or `psqlx conn rm`)");
    }

    let mut host = args.host.clone();
    let mut port = args.port;
    let mut db = args.db.clone();
    let mut user = args.user.clone();
    let mut sslmode = args.sslmode.clone();
    let mut description = args.description.clone();
    let mut url_password: Option<String> = None;

    if let Some(url) = &args.url {
        let parsed = parse_pg_url(url)?;
        host = host.or(parsed.host);
        port = port.or(parsed.port);
        db = db.or(parsed.database);
        user = user.or(parsed.user);
        sslmode = sslmode.or(parsed.sslmode);
        url_password = parsed.password;
    }

    // --- offer the paste-a-URL path ------------------------------------
    // Read hidden, because a URL with a password in it is itself a secret.
    // Nothing typed at these prompts reaches the shell's history.
    let nothing_given = args.url.is_none() && host.is_none() && db.is_none() && user.is_none();
    if interactive && nothing_given {
        eprintln!("\nEnter the connection details, or paste a postgres:// URL.");
        if confirm("Paste a connection URL?", false)? {
            loop {
                let raw = rpassword::prompt_password("Connection URL (hidden): ")?;
                let raw = raw.trim();
                if raw.is_empty() {
                    eprintln!("  Nothing pasted; falling back to field-by-field entry.");
                    break;
                }
                match parse_pg_url(raw) {
                    Ok(parsed) => {
                        eprintln!("  Parsed: {}", redact_url(&parsed));
                        host = parsed.host;
                        port = parsed.port;
                        db = parsed.database;
                        user = parsed.user;
                        sslmode = sslmode.take().or(parsed.sslmode);
                        url_password = parsed.password;
                        break;
                    }
                    Err(e) => {
                        eprintln!("  {e:#}");
                        if !confirm("Try again?", true)? {
                            break;
                        }
                    }
                }
            }
        }
    }

    // --- fields, prompting for whatever is still missing ----------------
    let host = match host {
        Some(h) => h,
        None if interactive => prompt("Host", Some("127.0.0.1"))?,
        None => bail!("--host is required (or pass --url)"),
    };
    let port = match port {
        Some(p) => p,
        None if interactive => prompt("Port", Some("5432"))?.parse().context("invalid port")?,
        None => 5432,
    };
    let db = match db {
        Some(d) => d,
        None if interactive => prompt("Database", None)?,
        None => bail!("--db is required (or pass --url)"),
    };
    let user = match user {
        Some(u) => u,
        None if interactive => prompt("User", None)?,
        None => bail!("--user is required (or pass --url)"),
    };

    // --- password ------------------------------------------------------
    let explicit_source = args.no_password
        || args.password_env.is_some()
        || args.password_command.is_some()
        || args.password_stdin;

    let password_source = if args.no_password {
        PasswordSource::None
    } else if let Some(var) = args.password_env.clone() {
        PasswordSource::Env { var }
    } else if let Some(command) = args.password_command.clone() {
        PasswordSource::Command { command }
    } else if args.password_stdin {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        let pw = buf.trim_end_matches(['\n', '\r']).to_string();
        if pw.is_empty() {
            bail!("--password-stdin was given but stdin was empty");
        }
        secrets::store(&name, &pw)?;
        PasswordSource::Keyring
    } else if let Some(pw) = url_password {
        secrets::store(&name, &pw)?;
        PasswordSource::Keyring
    } else if interactive {
        // Hidden input: safe to paste, never echoed, never in shell history.
        let pw = rpassword::prompt_password("Password (hidden, blank for none): ")?;
        if pw.is_empty() {
            PasswordSource::None
        } else {
            secrets::store(&name, &pw)?;
            PasswordSource::Keyring
        }
    } else {
        bail!(
            "no password source given. Pass one of --password-stdin, --password-env VAR, \
             --password-command CMD, or --no-password — or run `psqlx conn add {name}` \
             from a terminal to be prompted."
        );
    };
    let _ = explicit_source;

    // --- remaining optional fields --------------------------------------
    let sslmode = match sslmode {
        Some(s) => s,
        None if interactive => prompt("SSL mode", Some("prefer"))?,
        None => "prefer".to_string(),
    };
    if description.is_none() && interactive && args.name.is_none() {
        let d = prompt_optional("Description (optional)")?;
        description = d;
    }

    let mode = Mode::parse(&args.mode)?;
    let conn = Connection {
        description,
        host,
        port,
        database: db,
        user,
        password: password_source,
        sslmode,
        sslrootcert: args.sslrootcert.clone(),
        connect_timeout: "10s".into(),
        policy: Policy {
            mode,
            ..Policy::default()
        },
    };

    // --- confirm ---------------------------------------------------------
    if interactive {
        eprintln!("\n  name      {name}");
        eprintln!("  target    {}", conn.summary());
        eprintln!("  sslmode   {}", conn.sslmode);
        eprintln!("  password  {} (never printed back)", conn.password.label());
        eprintln!("  policy    {}", mode.as_str());
        if !confirm("\nSave this connection?", true)? {
            // Don't leave an orphaned secret behind.
            if matches!(conn.password, PasswordSource::Keyring) {
                let _ = secrets::delete(&name);
            }
            eprintln!("Cancelled; nothing was saved.");
            return Ok(());
        }
    }

    let summary = conn.summary();
    let set_default = args.set_default || cfg.default_connection.is_none();
    cfg.connections.insert(name.clone(), conn);
    if set_default {
        cfg.default_connection = Some(name.clone());
    }
    cfg.save()?;

    println!("Added connection '{name}' -> {summary}");
    println!("Policy: {} (default)", mode.as_str());
    if set_default {
        println!("Set as the default connection.");
    }

    // --- verify it actually works ----------------------------------------
    if interactive && !args.no_test {
        eprint!("\nTesting connection... ");
        match conn_probe(&name).await {
            Ok(server) => eprintln!("ok — {server}"),
            Err(e) => {
                eprintln!("failed.\n  {e:#}");
                eprintln!(
                    "\nThe connection was saved anyway. Fix it with `psqlx conn edit {name} ...` \
                     or `psqlx conn set-password {name}`, then re-run `psqlx conn test {name}`."
                );
                return Ok(());
            }
        }
    }

    println!("\nQuery it: psqlx query {name} \"select 1\"");
    Ok(())
}

/// Connect and return a one-line description of the server.
async fn conn_probe(name: &str) -> Result<String> {
    let (_, conn, client) = open(Some(name)).await?;
    let sets = introspect::probe(&client, &conn.policy).await?;
    let row = sets
        .first()
        .and_then(|s| s.rows.first())
        .ok_or_else(|| anyhow::anyhow!("server returned no rows"))?;
    let get = |i: usize| row.get(i).cloned().flatten().unwrap_or_default();
    let server = get(2);
    let version = server.split(" on ").next().unwrap_or(&server).to_string();
    Ok(format!("{version}, as {} on {}", get(1), get(0)))
}

/// `postgres://user:****@host:port/db`, safe to show back to the user.
fn redact_url(p: &ParsedUrl) -> String {
    let mut s = String::from("postgres://");
    if let Some(u) = &p.user {
        s.push_str(u);
        if p.password.is_some() {
            s.push_str(":****");
        }
        s.push('@');
    }
    s.push_str(p.host.as_deref().unwrap_or("?"));
    if let Some(port) = p.port {
        s.push_str(&format!(":{port}"));
    }
    s.push('/');
    s.push_str(p.database.as_deref().unwrap_or("?"));
    if let Some(m) = &p.sslmode {
        s.push_str(&format!("?sslmode={m}"));
    }
    s
}

fn conn_list() -> Result<()> {
    let cfg = Config::load()?;
    if cfg.connections.is_empty() {
        println!("No connections yet. Add one with:\n  psqlx conn add prod --host ... --db ... --user ...");
        return Ok(());
    }
    let mut sets = output::ResultSet {
        columns: vec![
            "name".into(),
            "target".into(),
            "mode".into(),
            "password".into(),
            "default".into(),
        ],
        ..Default::default()
    };
    for (name, c) in &cfg.connections {
        sets.rows.push(vec![
            Some(name.clone()),
            Some(c.summary()),
            Some(c.policy.mode.as_str().to_string()),
            Some(c.password.label()),
            Some(
                if cfg.default_connection.as_deref() == Some(name.as_str()) {
                    "yes"
                } else {
                    ""
                }
                .to_string(),
            ),
        ]);
    }
    print!("{}", output::render(&[sets], Format::Table)?);
    Ok(())
}

fn conn_show(name: &str) -> Result<()> {
    let cfg = Config::load()?;
    let (name, c) = cfg.resolve(Some(name))?;
    println!("name:            {name}");
    if let Some(d) = &c.description {
        println!("description:     {d}");
    }
    println!("host:            {}", c.host);
    println!("port:            {}", c.port);
    println!("database:        {}", c.database);
    println!("user:            {}", c.user);
    println!("password:        {} (never printed)", c.password.label());
    println!("sslmode:         {}", c.sslmode);
    if let Some(ca) = &c.sslrootcert {
        println!("sslrootcert:     {ca}");
    }
    println!();
    print_policy(&c.policy);
    Ok(())
}

fn print_policy(p: &Policy) {
    println!("policy.mode:               {}", p.mode.as_str());
    println!("policy.max_rows:           {}", p.max_rows);
    println!("policy.statement_timeout:  {}", p.statement_timeout);
    println!("policy.lock_timeout:       {}", p.lock_timeout);
    println!("policy.max_statements:     {}", p.max_statements);
    if !p.deny_tables.is_empty() {
        println!("policy.deny_tables:        {}", p.deny_tables.join(", "));
    }
    if !p.allow_write_tables.is_empty() {
        println!("policy.allow_write_tables: {}", p.allow_write_tables.join(", "));
    }
}

fn conn_edit(args: EditArgs) -> Result<()> {
    let mut cfg = Config::load()?;
    let c = cfg
        .connections
        .get_mut(&args.name)
        .with_context(|| format!("unknown connection '{}'", args.name))?;
    if let Some(v) = args.host {
        c.host = v;
    }
    if let Some(v) = args.port {
        c.port = v;
    }
    if let Some(v) = args.db {
        c.database = v;
    }
    if let Some(v) = args.user {
        c.user = v;
    }
    if let Some(v) = args.description {
        c.description = Some(v);
    }
    if let Some(v) = args.sslmode {
        c.sslmode = v;
    }
    if let Some(v) = args.sslrootcert {
        c.sslrootcert = Some(v);
    }
    let summary = c.summary();
    cfg.save()?;
    println!("Updated '{}' -> {}", args.name, summary);
    Ok(())
}

fn conn_rm(name: &str) -> Result<()> {
    let mut cfg = Config::load()?;
    if cfg.connections.remove(name).is_none() {
        bail!("unknown connection '{name}'");
    }
    if cfg.default_connection.as_deref() == Some(name) {
        cfg.default_connection = cfg.connections.keys().next().cloned();
    }
    cfg.save()?;
    secrets::delete(name)?;
    println!("Removed connection '{name}' and its stored password.");
    Ok(())
}

fn conn_default(name: &str) -> Result<()> {
    let mut cfg = Config::load()?;
    if !cfg.connections.contains_key(name) {
        bail!("unknown connection '{name}'");
    }
    cfg.default_connection = Some(name.to_string());
    cfg.save()?;
    println!("Default connection is now '{name}'.");
    Ok(())
}

fn conn_set_password(name: &str) -> Result<()> {
    let mut cfg = Config::load()?;
    if !cfg.connections.contains_key(name) {
        bail!("unknown connection '{name}'");
    }
    let pw = if std::io::stdin().is_terminal() {
        rpassword::prompt_password("Password: ")?
    } else {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf.trim_end_matches(['\n', '\r']).to_string()
    };
    if pw.is_empty() {
        bail!("empty password; use `psqlx conn edit` if this connection needs no password");
    }
    secrets::store(name, &pw)?;
    if let Some(c) = cfg.connections.get_mut(name) {
        c.password = PasswordSource::Keyring;
    }
    cfg.save()?;
    println!("Stored password for '{name}' in the keychain.");
    Ok(())
}

async fn conn_test(name: &str) -> Result<()> {
    let (name, conn, client) = open(Some(name)).await?;
    let sets = introspect::probe(&client, &conn.policy).await?;
    print!("{}", output::render(&sets, Format::Table)?);
    eprintln!(
        "-- psqlx: {name} reachable, policy {}",
        conn.policy.mode.as_str()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// policy
// ---------------------------------------------------------------------------

fn policy_cmd(cmd: PolicyCmd) -> Result<()> {
    match cmd {
        PolicyCmd::Show { connection } => {
            let cfg = Config::load()?;
            let (name, c) = cfg.resolve(connection.as_deref().or(env_default().as_deref()))?;
            println!("connection: {name}\n");
            print_policy(&c.policy);
            Ok(())
        }
        PolicyCmd::Set(args) => {
            let mut cfg = Config::load()?;
            let c = cfg
                .connections
                .get_mut(&args.connection)
                .with_context(|| format!("unknown connection '{}'", args.connection))?;

            if let Some(m) = &args.mode {
                c.policy.mode = Mode::parse(m)?;
            }
            if let Some(n) = args.max_rows {
                c.policy.max_rows = n;
            }
            if let Some(t) = &args.statement_timeout {
                config::parse_duration(t).context("--statement-timeout")?;
                c.policy.statement_timeout = t.clone();
            }
            if let Some(t) = &args.lock_timeout {
                config::parse_duration(t).context("--lock-timeout")?;
                c.policy.lock_timeout = t.clone();
            }
            if let Some(n) = args.max_statements {
                c.policy.max_statements = n;
            }
            if args.clear_deny_tables {
                c.policy.deny_tables.clear();
            }
            for t in args.deny_tables {
                if !c.policy.deny_tables.contains(&t) {
                    c.policy.deny_tables.push(t);
                }
            }
            if args.clear_allow_write_tables {
                c.policy.allow_write_tables.clear();
            }
            for t in args.allow_write_tables {
                if !c.policy.allow_write_tables.contains(&t) {
                    c.policy.allow_write_tables.push(t);
                }
            }

            let mode = c.policy.mode;
            let policy = c.policy.clone();
            cfg.save()?;
            println!("Updated policy for '{}'.\n", args.connection);
            print_policy(&policy);
            if mode != Mode::ReadOnly {
                eprintln!(
                    "\nWarning: '{}' can now modify data. Writes still roll back unless the caller \
                     passes --commit.",
                    args.connection
                );
            }
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

struct ParsedUrl {
    host: Option<String>,
    port: Option<u16>,
    database: Option<String>,
    user: Option<String>,
    password: Option<String>,
    sslmode: Option<String>,
}

fn parse_pg_url(raw: &str) -> Result<ParsedUrl> {
    let u = url::Url::parse(raw).context("parsing connection URL")?;
    if !matches!(u.scheme(), "postgres" | "postgresql") {
        bail!("connection URL must start with postgres:// or postgresql://");
    }
    let sslmode = u
        .query_pairs()
        .find(|(k, _)| k == "sslmode")
        .map(|(_, v)| v.into_owned());
    Ok(ParsedUrl {
        host: u.host_str().map(|s| s.to_string()),
        port: u.port(),
        database: {
            let p = u.path().trim_start_matches('/');
            if p.is_empty() {
                None
            } else {
                Some(percent_decode(p))
            }
        },
        user: {
            let name = u.username();
            if name.is_empty() {
                None
            } else {
                Some(percent_decode(name))
            }
        },
        password: u.password().map(percent_decode),
        sslmode,
    })
}

fn percent_decode(s: &str) -> String {
    // url::Url already decodes host/port; username, password and path need it.
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn prompt(label: &str, default: Option<&str>) -> Result<String> {
    let mut out = std::io::stderr();
    match default {
        Some(d) => write!(out, "{label} [{d}]: ")?,
        None => write!(out, "{label}: ")?,
    }
    out.flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let line = line.trim().to_string();
    if line.is_empty() {
        match default {
            Some(d) => Ok(d.to_string()),
            None => bail!("{label} is required"),
        }
    } else {
        Ok(line)
    }
}

/// Like `prompt`, but an empty answer means "not set" rather than an error.
fn prompt_optional(label: &str) -> Result<Option<String>> {
    let mut out = std::io::stderr();
    write!(out, "{label}: ")?;
    out.flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let line = line.trim().to_string();
    Ok(if line.is_empty() { None } else { Some(line) })
}

fn confirm(question: &str, default_yes: bool) -> Result<bool> {
    let mut out = std::io::stderr();
    write!(out, "{question} [{}] ", if default_yes { "Y/n" } else { "y/N" })?;
    out.flush()?;
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line)? == 0 {
        return Ok(default_yes); // EOF
    }
    match line.trim().to_ascii_lowercase().as_str() {
        "" => Ok(default_yes),
        "y" | "yes" => Ok(true),
        _ => Ok(false),
    }
}

fn guide_text() -> String {
    r#"psqlx — database access for agents

You do not have, and do not need, database credentials. Connections are
pre-configured. Use these commands:

  psqlx conn list                       list the connections you can use
  psqlx query <conn> "<sql>"            run SQL
  psqlx tables <conn>                   list tables and views
  psqlx describe <conn> <table>         columns, indexes, constraints
  psqlx schemas <conn>                  list schemas

Notes:

  * Connections are read-only by default. Every query runs inside
    BEGIN TRANSACTION READ ONLY and is rolled back, so nothing you run can
    change data. INSERT/UPDATE/DELETE/DDL are rejected before they are sent.
  * Results are capped (default 1000 rows). Add LIMIT yourself, or pass
    --max-rows N.
  * Output is an aligned table by default. Use --format json when you want to
    parse it, or --format csv / --format markdown.
  * psql meta-commands (\d, \dt, \l) do not work. Use `psqlx describe` and
    `psqlx tables` instead.
  * A rejected query exits with status 3 and explains which rule it hit.
    Rewrite the query as a read; do not try to work around the policy.

Examples:

  psqlx query prod "select count(*) from users where created_at > now() - interval '7 days'"
  psqlx query prod --format json "select id, email from users limit 5"
  psqlx describe prod public.orders
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_vs_connection_name() {
        assert!(looks_like_sql("select 1"));
        assert!(looks_like_sql("select * from t"));
        assert!(!looks_like_sql("prod"));
        assert!(!looks_like_sql("prod-replica"));
    }

    #[test]
    fn parses_pg_urls() {
        let p = parse_pg_url("postgres://alice:s3cr3t@db.example.com:6543/app?sslmode=require").unwrap();
        assert_eq!(p.host.as_deref(), Some("db.example.com"));
        assert_eq!(p.port, Some(6543));
        assert_eq!(p.database.as_deref(), Some("app"));
        assert_eq!(p.user.as_deref(), Some("alice"));
        assert_eq!(p.password.as_deref(), Some("s3cr3t"));
        assert_eq!(p.sslmode.as_deref(), Some("require"));
    }

    #[test]
    fn percent_decodes_credentials() {
        let p = parse_pg_url("postgres://user%40corp:p%40ss@localhost/db").unwrap();
        assert_eq!(p.user.as_deref(), Some("user@corp"));
        assert_eq!(p.password.as_deref(), Some("p@ss"));
    }

    #[test]
    fn rejects_non_postgres_urls() {
        assert!(parse_pg_url("mysql://localhost/db").is_err());
    }

    #[test]
    fn connection_names_are_validated() {
        assert!(validate_name("prod").is_ok());
        assert!(validate_name("prod-replica_1.eu").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name("../etc/passwd").is_err());
        assert!(validate_name("a b").is_err());
    }
}
