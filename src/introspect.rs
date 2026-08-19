//! Schema introspection.
//!
//! psqlx never shells out to psql, so `\dt` and `\d` are not available. These
//! commands cover the same ground with catalog queries that psqlx writes
//! itself — the agent supplies only an identifier, never SQL, and every query
//! still runs inside the read-only transaction.

use crate::config::Policy;
use crate::output::ResultSet;
use anyhow::{Context, Result};
use tokio_postgres::Client;
use tokio_postgres::types::ToSql;

async fn begin_read_only(client: &Client, policy: &Policy) -> Result<()> {
    client
        .simple_query("BEGIN TRANSACTION READ ONLY")
        .await
        .context("starting read-only transaction")?;
    client
        .simple_query(&format!(
            "SET LOCAL statement_timeout = {}; SET LOCAL lock_timeout = {};",
            policy.statement_timeout_ms()?,
            policy.lock_timeout_ms()?
        ))
        .await
        .context("applying statement guards")?;
    Ok(())
}

async fn collect(
    client: &Client,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    label: &str,
) -> Result<ResultSet> {
    let db_err = |e: tokio_postgres::Error| {
        if let Some(db) = e.as_db_error() {
            anyhow::anyhow!("{}", db.message())
        } else {
            anyhow::anyhow!(e)
        }
    };

    // Prepare first so we know the column names even when there are no rows —
    // an empty "indexes" section should still print its header.
    let stmt = client.prepare(sql).await.map_err(db_err)?;
    let columns: Vec<String> = stmt.columns().iter().map(|c| c.name().to_string()).collect();
    let rows = client.query(&stmt, params).await.map_err(db_err)?;

    let mut out_rows = Vec::with_capacity(rows.len());
    for row in &rows {
        let mut values = Vec::with_capacity(columns.len());
        for i in 0..columns.len() {
            values.push(row.try_get::<_, Option<String>>(i).unwrap_or(None));
        }
        out_rows.push(values);
    }

    Ok(ResultSet {
        columns,
        rows: out_rows,
        command: None,
        truncated: false,
        statement: label.to_string(),
    })
}

const TABLES_SQL: &str = r#"
SELECT n.nspname::text                                            AS schema,
       c.relname::text                                            AS name,
       CASE c.relkind
            WHEN 'r' THEN 'table'
            WHEN 'p' THEN 'partitioned table'
            WHEN 'v' THEN 'view'
            WHEN 'm' THEN 'materialized view'
            WHEN 'f' THEN 'foreign table'
       END                                                        AS type,
       CASE WHEN c.reltuples < 0 THEN NULL
            ELSE c.reltuples::bigint::text END                    AS approx_rows,
       pg_size_pretty(pg_total_relation_size(c.oid))              AS size
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND n.nspname NOT LIKE 'pg_toast%'
  AND n.nspname NOT LIKE 'pg_temp%'
  AND ($1::text IS NULL OR n.nspname = $1::text)
ORDER BY 1, 2
"#;

pub async fn tables(client: &Client, policy: &Policy, schema: Option<&str>) -> Result<Vec<ResultSet>> {
    begin_read_only(client, policy).await?;
    let result = collect(client, TABLES_SQL, &[&schema], "tables").await;
    let _ = client.simple_query("ROLLBACK").await;
    Ok(vec![result?])
}

const COLUMNS_SQL: &str = r#"
SELECT a.attname::text                                              AS column,
       format_type(a.atttypid, a.atttypmod)                         AS type,
       CASE WHEN a.attnotnull THEN 'not null' ELSE '' END           AS nullable,
       COALESCE(pg_get_expr(d.adbin, d.adrelid), '')                AS default,
       COALESCE(col_description(a.attrelid, a.attnum), '')          AS comment
FROM pg_attribute a
LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
WHERE a.attrelid = $1::text::regclass
  AND a.attnum > 0
  AND NOT a.attisdropped
ORDER BY a.attnum
"#;

const INDEXES_SQL: &str = r#"
SELECT i.relname::text                  AS index,
       pg_get_indexdef(x.indexrelid)    AS definition
FROM pg_index x
JOIN pg_class i ON i.oid = x.indexrelid
WHERE x.indrelid = $1::text::regclass
ORDER BY 1
"#;

const CONSTRAINTS_SQL: &str = r#"
SELECT conname::text                    AS constraint,
       pg_get_constraintdef(oid)        AS definition
FROM pg_constraint
WHERE conrelid = $1::text::regclass
ORDER BY 1
"#;

pub async fn describe(client: &Client, policy: &Policy, table: &str) -> Result<Vec<ResultSet>> {
    begin_read_only(client, policy).await?;

    let run = async {
        let cols = collect(client, COLUMNS_SQL, &[&table], &format!("columns of {table}"))
            .await
            .with_context(|| {
                format!("could not describe '{table}' — check the name, and qualify it with a schema if it is not on the search_path")
            })?;
        let idx = collect(client, INDEXES_SQL, &[&table], &format!("indexes of {table}")).await?;
        let cons = collect(
            client,
            CONSTRAINTS_SQL,
            &[&table],
            &format!("constraints of {table}"),
        )
        .await?;
        Ok::<_, anyhow::Error>(vec![cols, idx, cons])
    }
    .await;

    let _ = client.simple_query("ROLLBACK").await;
    run
}

const SCHEMAS_SQL: &str = r#"
SELECT n.nspname::text                                      AS schema,
       count(c.oid) FILTER (WHERE c.relkind IN ('r','p'))::text AS tables,
       count(c.oid) FILTER (WHERE c.relkind IN ('v','m'))::text AS views,
       pg_size_pretty(COALESCE(sum(pg_total_relation_size(c.oid))
                      FILTER (WHERE c.relkind IN ('r','p','m')), 0)) AS size
FROM pg_namespace n
LEFT JOIN pg_class c ON c.relnamespace = n.oid
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND n.nspname NOT LIKE 'pg_toast%'
  AND n.nspname NOT LIKE 'pg_temp%'
GROUP BY n.nspname
ORDER BY 1
"#;

pub async fn schemas(client: &Client, policy: &Policy) -> Result<Vec<ResultSet>> {
    begin_read_only(client, policy).await?;
    let result = collect(client, SCHEMAS_SQL, &[], "schemas").await;
    let _ = client.simple_query("ROLLBACK").await;
    Ok(vec![result?])
}

/// A cheap connectivity + privilege probe used by `psqlx conn test`.
pub async fn probe(client: &Client, policy: &Policy) -> Result<Vec<ResultSet>> {
    begin_read_only(client, policy).await?;
    let sql = r#"
SELECT current_database()::text                     AS database,
       current_user::text                           AS "user",
       version()                                    AS server,
       CASE WHEN pg_is_in_recovery() THEN 'replica' ELSE 'primary' END AS role,
       current_setting('transaction_read_only')     AS txn_read_only
"#;
    let result = collect(client, sql, &[], "probe").await;
    let _ = client.simple_query("ROLLBACK").await;
    Ok(vec![result?])
}
