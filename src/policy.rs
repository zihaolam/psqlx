//! Statement classification and policy enforcement.
//!
//! This is the *first* of three layers that keep a query read-only. It is the
//! one that produces good error messages; it is not the one you should bet the
//! database on. See `exec.rs` for layers two and three:
//!
//!   1. this parser        — rejects the statement before it is ever sent
//!   2. `BEGIN TRANSACTION READ ONLY` + unconditional `ROLLBACK`
//!   3. the Postgres role you connect as (grant it `SELECT` and nothing else)

use crate::config::{Mode, Policy};
use crate::sqlparse::{Statement, Tok};
use anyhow::{Result, bail};

/// Statement verbs that only read.
const READ_VERBS: &[&str] = &["select", "with", "table", "values", "show", "explain"];

/// Verbs that write rows but are not DDL.
const DML_WRITE_VERBS: &[&str] = &["insert", "update", "delete", "merge"];

/// Keywords that can introduce a write from *anywhere* in a statement, most
/// notably inside a data-modifying CTE: `WITH x AS (DELETE ... RETURNING *)`.
/// Every other write verb can only appear at the very start of a statement, so
/// the verb allow-list catches it and we avoid false positives on column names
/// like `grant`, `comment` or `copy`.
const NESTED_WRITE_WORDS: &[&str] = &["insert", "update", "delete", "merge", "into"];

/// Functions that sidestep the read-only transaction, read the filesystem, run
/// arbitrary SQL on another connection, or can wedge the server.
const DENIED_FUNCTIONS: &[&str] = &[
    // opens a second connection, so the read-only transaction does not apply
    "dblink",
    "dblink_exec",
    "dblink_send_query",
    "dblink_open",
    // filesystem access
    "pg_read_file",
    "pg_read_binary_file",
    "pg_ls_dir",
    "pg_stat_file",
    "lo_import",
    "lo_export",
    "lo_get",
    "lo_put",
    // server / session control
    "pg_terminate_backend",
    "pg_cancel_backend",
    "pg_reload_conf",
    "pg_rotate_logfile",
    "pg_promote",
    "pg_switch_wal",
    "pg_create_restore_point",
    "pg_drop_replication_slot",
    "pg_create_physical_replication_slot",
    "pg_create_logical_replication_slot",
    "pg_replication_slot_advance",
    "pg_logical_emit_message",
    "set_config",
    "pg_stat_reset",
    "pg_stat_statements_reset",
    // denial of service
    "pg_sleep",
    "pg_sleep_for",
    "pg_sleep_until",
    "pg_advisory_lock",
    "pg_advisory_lock_shared",
    "pg_advisory_xact_lock",
    "pg_try_advisory_lock",
    // run SQL from a string, bypassing this parser
    "query_to_xml",
    "query_to_xmlschema",
    "query_to_xml_and_xmlschema",
];

/// Catalogs holding credentials or credential hashes. Reading these is exactly
/// the thing psqlx exists to prevent, so they are blocked in every mode except
/// `unrestricted`.
const DENIED_CATALOGS: &[&str] = &["pg_authid", "pg_shadow", "pg_user_mapping", "pg_user_mappings"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Read,
    Write,
    Ddl,
    Other,
}

#[derive(Debug, Clone)]
pub struct StmtPlan {
    pub sql: String,
    pub verb: String,
    pub kind: Kind,
    /// Safe to wrap in `SELECT * FROM (...) LIMIT n` for server-side row capping.
    pub wrappable: bool,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub statements: Vec<StmtPlan>,
}

impl Plan {
    pub fn has_writes(&self) -> bool {
        self.statements
            .iter()
            .any(|s| matches!(s.kind, Kind::Write | Kind::Ddl))
    }
}

/// Check a whole script against a policy.
pub fn evaluate(stmts: &[Statement], policy: &Policy) -> Result<Plan> {
    if stmts.is_empty() {
        bail!("no SQL statement found");
    }
    if policy.max_statements > 0 && stmts.len() > policy.max_statements {
        bail!(
            "{} statements in one call exceeds the max_statements limit of {}",
            stmts.len(),
            policy.max_statements
        );
    }

    let mut plans = Vec::with_capacity(stmts.len());
    for stmt in stmts {
        plans.push(check_one(stmt, policy)?);
    }
    Ok(Plan { statements: plans })
}

fn check_one(stmt: &Statement, policy: &Policy) -> Result<StmtPlan> {
    if stmt.sql.starts_with('\\') {
        bail!(
            "psql meta-commands are not supported (psqlx does not shell out to psql).\n\
             Use `psqlx tables <conn>` and `psqlx describe <conn> <table>` instead of \\dt and \\d."
        );
    }

    let verb = stmt
        .verb()
        .ok_or_else(|| anyhow::anyhow!("could not find a statement verb in: {}", preview(&stmt.sql)))?
        .to_string();

    let nested_write = NESTED_WRITE_WORDS.iter().any(|w| stmt.has_word(w));
    let is_read_verb = READ_VERBS.contains(&verb.as_str());
    let is_dml_verb = DML_WRITE_VERBS.contains(&verb.as_str());

    let kind = if is_dml_verb || (is_read_verb && nested_write) {
        Kind::Write
    } else if is_read_verb {
        Kind::Read
    } else if matches!(
        verb.as_str(),
        "create" | "alter" | "drop" | "truncate" | "comment" | "grant" | "revoke" | "refresh"
    ) {
        Kind::Ddl
    } else {
        Kind::Other
    };

    // --- mode gate -----------------------------------------------------
    match policy.mode {
        Mode::ReadOnly => {
            if !is_read_verb {
                bail!(
                    "`{}` is blocked: connection policy is read-only, which allows only {}.\n\
                     Statement: {}",
                    verb.to_uppercase(),
                    READ_VERBS.join(", ").to_uppercase(),
                    preview(&stmt.sql)
                );
            }
            if nested_write {
                let word = NESTED_WRITE_WORDS
                    .iter()
                    .find(|w| stmt.has_word(w))
                    .unwrap();
                bail!(
                    "blocked: read-only policy, but this statement contains `{}` \
                     (a data-modifying CTE, SELECT INTO or locking clause).\nStatement: {}",
                    word.to_uppercase(),
                    preview(&stmt.sql)
                );
            }
        }
        Mode::ReadWrite => {
            if !is_read_verb && !is_dml_verb {
                bail!(
                    "`{}` is blocked: connection policy is read-write, which allows reads plus {} \
                     but no DDL.\nStatement: {}",
                    verb.to_uppercase(),
                    DML_WRITE_VERBS.join(", ").to_uppercase(),
                    preview(&stmt.sql)
                );
            }
            if kind == Kind::Write && !policy.allow_write_tables.is_empty() {
                let target = write_target(stmt, &verb);
                match target {
                    Some(t)
                        if policy
                            .allow_write_tables
                            .iter()
                            .any(|a| a.eq_ignore_ascii_case(&t)) => {}
                    Some(t) => bail!(
                        "blocked: writes to `{t}` are not allowed. allow_write_tables = [{}]",
                        policy.allow_write_tables.join(", ")
                    ),
                    None => bail!(
                        "blocked: could not determine the write target, and allow_write_tables is set.\n\
                         Statement: {}",
                        preview(&stmt.sql)
                    ),
                }
            }
        }
        Mode::Unrestricted => {}
    }

    // --- checks that apply regardless of verb --------------------------
    if policy.mode != Mode::Unrestricted {
        for f in stmt.called_functions() {
            if DENIED_FUNCTIONS.contains(&f.as_str()) {
                bail!(
                    "blocked: `{f}()` is on the denied-function list — it can read the filesystem, \
                     open a second connection, or stall the server, all of which escape the \
                     read-only transaction."
                );
            }
        }
        let idents = stmt.identifiers();
        for cat in DENIED_CATALOGS {
            if idents.iter().any(|i| i == cat) {
                bail!("blocked: `{cat}` holds credentials and is never readable through psqlx.");
            }
        }
    }

    if !policy.deny_tables.is_empty() {
        let idents = stmt.identifiers();
        for denied in &policy.deny_tables {
            let d = denied.to_ascii_lowercase();
            // Match either the whole dotted name or any single segment, so
            // `deny_tables = ["users"]` blocks `public.users` too.
            let hit = idents.iter().any(|i| *i == d)
                || d.split('.').next_back().is_some_and(|last| idents.iter().any(|i| i == last));
            if hit {
                bail!("blocked: `{denied}` is on this connection's deny_tables list.");
            }
        }
    }

    let wrappable = matches!(verb.as_str(), "select" | "with" | "table" | "values") && kind == Kind::Read;

    Ok(StmtPlan {
        sql: stmt.sql.clone(),
        verb,
        kind,
        wrappable,
    })
}

/// Best-effort extraction of the table a DML statement writes to.
fn write_target(stmt: &Statement, verb: &str) -> Option<String> {
    let toks = &stmt.toks;
    let anchor = match verb {
        "insert" | "merge" => "into",
        "update" => "update",
        "delete" => "from",
        _ => return None,
    };
    let pos = toks
        .iter()
        .position(|t| matches!(t, Tok::Word(w) if w == anchor))?;

    // Collect `schema . table`, or just `table`.
    let mut parts: Vec<String> = Vec::new();
    let mut i = pos + 1;
    loop {
        match toks.get(i) {
            Some(Tok::Word(w)) => parts.push(w.clone()),
            Some(Tok::QuotedIdent(w)) => parts.push(w.to_ascii_lowercase()),
            _ => break,
        }
        if matches!(toks.get(i + 1), Some(Tok::Punct('.'))) {
            i += 2;
            continue;
        }
        break;
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("."))
    }
}

fn preview(sql: &str) -> String {
    let one_line: String = sql.split_whitespace().collect::<Vec<_>>().join(" ");
    if one_line.chars().count() > 120 {
        let s: String = one_line.chars().take(117).collect();
        format!("{s}...")
    } else {
        one_line
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlparse::split;

    fn ro() -> Policy {
        Policy::default()
    }
    fn rw() -> Policy {
        Policy {
            mode: Mode::ReadWrite,
            ..Policy::default()
        }
    }

    fn check(sql: &str, p: &Policy) -> Result<Plan> {
        evaluate(&split(sql).unwrap(), p)
    }

    #[test]
    fn allows_plain_reads() {
        for sql in [
            "select * from users limit 10",
            "SELECT count(*) FROM orders",
            "with recent as (select * from t) select * from recent",
            "explain analyze select 1",
            "show timezone",
            "table users",
            "values (1),(2)",
            "select * from t fetch first 10 rows only",
        ] {
            assert!(check(sql, &ro()).is_ok(), "should allow: {sql}");
        }
    }

    #[test]
    fn blocks_writes_in_read_only() {
        for sql in [
            "insert into users values (1)",
            "update users set name='x'",
            "delete from users",
            "truncate users",
            "drop table users",
            "create table t (a int)",
            "alter table t add column b int",
            "grant select on t to bob",
            "copy t from '/etc/passwd'",
            "call do_thing()",
            "do $$ begin end $$",
            "vacuum full",
            "set role postgres",
            "begin",
            "commit",
            "lock table users in access exclusive mode",
            "select * from t for update",
            "select * into backup from users",
            "with d as (delete from users returning *) select * from d",
            "with i as (insert into t values (1) returning *) select * from i",
        ] {
            assert!(check(sql, &ro()).is_err(), "should block: {sql}");
        }
    }

    #[test]
    fn injection_via_semicolon_is_caught() {
        assert!(check("select 1; drop table users", &ro()).is_err());
    }

    /// A COMMIT in the middle of a script would end the read-only transaction
    /// psqlx opened and leave the session in autocommit read-write mode. The
    /// verb allow-list has to catch every spelling of transaction control --
    /// including END and ABORT, which are synonyms for COMMIT and ROLLBACK.
    #[test]
    fn blocks_transaction_control_in_every_mode() {
        for sql in [
            "commit",
            "COMMIT",
            "end",
            "abort",
            "begin",
            "begin transaction read write",
            "start transaction",
            "rollback",
            "savepoint sp1",
            "release savepoint sp1",
            "rollback to savepoint sp1",
            "commit prepared 'x'",
            "prepare transaction 'x'",
            "set transaction read write",
            "set session characteristics as transaction read write",
            "reset all",
            "discard all",
        ] {
            assert!(check(sql, &ro()).is_err(), "read-only should block: {sql}");
            assert!(check(sql, &rw()).is_err(), "read-write should block: {sql}");
        }
    }

    #[test]
    fn escape_via_commit_then_write_is_caught() {
        // Every statement in a script is checked, so the write is rejected
        // before anything at all is sent to the server.
        for sql in [
            "select 1; commit; insert into users values (1)",
            "select 1; end; drop table users",
            "select 1; abort; begin; delete from users",
            "select 1; set session characteristics as transaction read write; update t set a=1",
        ] {
            assert!(check(sql, &ro()).is_err(), "should block: {sql}");
        }
    }

    #[test]
    fn write_keywords_in_strings_and_names_are_fine() {
        for sql in [
            "select 'delete from users' as note",
            "select created_at, updated_at, deleted_at from t",
            "select * from update_log",
            "select $$ insert into x $$",
            r#"select "insert" from weird"#,
        ] {
            assert!(check(sql, &ro()).is_ok(), "should allow: {sql}");
        }
    }

    #[test]
    fn blocks_dangerous_functions() {
        for sql in [
            "select pg_read_file('/etc/passwd')",
            "select pg_sleep(3600)",
            "select dblink('...','insert into t values(1)')",
            "select lo_export(1,'/tmp/x')",
            "select set_config('search_path','x',false)",
        ] {
            assert!(check(sql, &ro()).is_err(), "should block: {sql}");
        }
    }

    /// Quoting a function name does not change which function Postgres calls,
    /// so `"dblink"(...)` must be rejected exactly like `dblink(...)`. This is
    /// the parser bypass a pen test found: `called_functions()` used to look at
    /// bare words only, letting a quoted name reach the server — where `dblink`
    /// opens a second connection outside the read-only transaction and writes.
    #[test]
    fn blocks_dangerous_functions_even_when_quoted() {
        for sql in [
            r#"select "dblink"('conn','insert into t values(1)')"#,
            r#"select "pg_read_file"('/etc/passwd')"#,
            r#"select "pg_ls_dir"('/')"#,
            r#"select "set_config"('default_transaction_read_only','off',false)"#,
            r#"select "pg_sleep"(3600)"#,
            r#"select "lo_export"(1,'/tmp/x')"#,
        ] {
            assert!(check(sql, &ro()).is_err(), "should block: {sql}");
        }
    }

    #[test]
    fn blocks_credential_catalogs() {
        assert!(check("select * from pg_authid", &ro()).is_err());
        assert!(check("select rolpassword from pg_catalog.pg_authid", &ro()).is_err());
        assert!(check("select * from pg_shadow", &ro()).is_err());
    }

    #[test]
    fn read_write_mode_allows_dml_but_not_ddl() {
        assert!(check("insert into t values (1)", &rw()).is_ok());
        assert!(check("update t set a=1", &rw()).is_ok());
        assert!(check("drop table t", &rw()).is_err());
        assert!(check("select 1", &rw()).is_ok());
    }

    #[test]
    fn allow_write_tables_is_enforced() {
        let p = Policy {
            mode: Mode::ReadWrite,
            allow_write_tables: vec!["staging_events".into()],
            ..Policy::default()
        };
        assert!(check("insert into staging_events values (1)", &p).is_ok());
        assert!(check("update staging_events set a=1", &p).is_ok());
        assert!(check("delete from users", &p).is_err());
        assert!(check("insert into public.users values (1)", &p).is_err());
    }

    #[test]
    fn deny_tables_is_enforced() {
        let p = Policy {
            deny_tables: vec!["secrets".into()],
            ..Policy::default()
        };
        assert!(check("select * from secrets", &p).is_err());
        assert!(check("select * from public.secrets", &p).is_err());
        assert!(check("select * from other", &p).is_ok());
    }

    #[test]
    fn meta_commands_get_a_useful_error() {
        let err = check(r"\d users", &ro()).unwrap_err().to_string();
        assert!(err.contains("psqlx describe"), "got: {err}");
    }

    #[test]
    fn max_statements_enforced() {
        let p = Policy {
            max_statements: 2,
            ..Policy::default()
        };
        assert!(check("select 1; select 2", &p).is_ok());
        assert!(check("select 1; select 2; select 3", &p).is_err());
    }

    #[test]
    fn wrappable_only_for_row_returning_reads() {
        let plan = check("select 1", &ro()).unwrap();
        assert!(plan.statements[0].wrappable);
        let plan = check("show timezone", &ro()).unwrap();
        assert!(!plan.statements[0].wrappable);
        let plan = check("explain select 1", &ro()).unwrap();
        assert!(!plan.statements[0].wrappable);
    }
}
