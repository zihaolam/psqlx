//! Result rendering: aligned table (default), JSON, CSV, markdown.

use anyhow::{Result, bail};
use serde_json::{Map, Value, json};
use std::fmt::Write as _;
use unicode_width::UnicodeWidthStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Table,
    Json,
    Csv,
    Markdown,
}

impl Format {
    pub fn parse(s: &str) -> Result<Format> {
        match s.trim().to_ascii_lowercase().as_str() {
            "table" | "psql" | "aligned" => Ok(Format::Table),
            "json" => Ok(Format::Json),
            "csv" => Ok(Format::Csv),
            "md" | "markdown" => Ok(Format::Markdown),
            other => bail!("unknown format '{other}' (want table, json, csv, or markdown)"),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ResultSet {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Option<String>>>,
    /// e.g. "SELECT 12" — present for statements that return no rows.
    pub command: Option<String>,
    /// True when `max_rows` clipped the output.
    pub truncated: bool,
    pub statement: String,
}

impl ResultSet {
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }
}

pub fn render(sets: &[ResultSet], format: Format) -> Result<String> {
    let mut out = String::new();
    match format {
        Format::Json => {
            let payload: Vec<Value> = sets.iter().map(json_of).collect();
            let v = if payload.len() == 1 {
                payload.into_iter().next().unwrap()
            } else {
                Value::Array(payload)
            };
            out.push_str(&serde_json::to_string_pretty(&v)?);
            out.push('\n');
        }
        Format::Csv => {
            for (i, s) in sets.iter().enumerate() {
                if i > 0 {
                    out.push('\n');
                }
                out.push_str(&csv_of(s));
            }
        }
        Format::Table | Format::Markdown => {
            for (i, s) in sets.iter().enumerate() {
                if i > 0 {
                    out.push('\n');
                }
                if sets.len() > 1 {
                    let _ = writeln!(out, "-- {}", one_line(&s.statement));
                }
                if s.columns.is_empty() {
                    if let Some(cmd) = &s.command {
                        let _ = writeln!(out, "{cmd}");
                    }
                    continue;
                }
                out.push_str(&if format == Format::Markdown {
                    markdown_of(s)
                } else {
                    table_of(s)
                });
            }
        }
    }
    Ok(out)
}

fn json_of(s: &ResultSet) -> Value {
    let rows: Vec<Value> = s
        .rows
        .iter()
        .map(|r| {
            let mut m = Map::new();
            for (i, col) in s.columns.iter().enumerate() {
                let v = match r.get(i).and_then(|v| v.clone()) {
                    Some(text) => Value::String(text),
                    None => Value::Null,
                };
                // Duplicate column names: keep the last, but don't lose data —
                // suffix the collision.
                if m.contains_key(col) {
                    m.insert(format!("{col}_{i}"), v);
                } else {
                    m.insert(col.clone(), v);
                }
            }
            Value::Object(m)
        })
        .collect();

    json!({
        "columns": s.columns,
        "rows": rows,
        "row_count": s.rows.len(),
        "truncated": s.truncated,
        "command": s.command,
    })
}

fn csv_escape(v: &str) -> String {
    if v.contains(['"', ',', '\n', '\r']) {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v.to_string()
    }
}

fn csv_of(s: &ResultSet) -> String {
    let mut out = String::new();
    if s.columns.is_empty() {
        if let Some(cmd) = &s.command {
            let _ = writeln!(out, "{cmd}");
        }
        return out;
    }
    let _ = writeln!(
        out,
        "{}",
        s.columns.iter().map(|c| csv_escape(c)).collect::<Vec<_>>().join(",")
    );
    for row in &s.rows {
        let cells: Vec<String> = row
            .iter()
            .map(|c| csv_escape(c.as_deref().unwrap_or("")))
            .collect();
        let _ = writeln!(out, "{}", cells.join(","));
    }
    out
}

fn markdown_of(s: &ResultSet) -> String {
    let mut out = String::new();
    let esc = |v: &str| v.replace('|', "\\|").replace('\n', "<br>");
    let _ = writeln!(
        out,
        "| {} |",
        s.columns.iter().map(|c| esc(c)).collect::<Vec<_>>().join(" | ")
    );
    let _ = writeln!(
        out,
        "|{}|",
        s.columns.iter().map(|_| " --- ").collect::<Vec<_>>().join("|")
    );
    for row in &s.rows {
        let cells: Vec<String> = row
            .iter()
            .map(|c| esc(c.as_deref().unwrap_or("NULL")))
            .collect();
        let _ = writeln!(out, "| {} |", cells.join(" | "));
    }
    let _ = writeln!(out, "\n({} rows{})", s.rows.len(), if s.truncated { ", truncated" } else { "" });
    out
}

const NULL: &str = "NULL";

/// psql-ish aligned output. Multi-line values are flattened so the grid stays
/// readable; use `--format json` when you need them verbatim.
fn table_of(s: &ResultSet) -> String {
    let cells: Vec<Vec<String>> = s
        .rows
        .iter()
        .map(|r| {
            (0..s.columns.len())
                .map(|i| match r.get(i) {
                    Some(Some(v)) => v.replace('\n', "\\n").replace('\r', ""),
                    _ => NULL.to_string(),
                })
                .collect()
        })
        .collect();

    let mut widths: Vec<usize> = s.columns.iter().map(|c| UnicodeWidthStr::width(c.as_str())).collect();
    for row in &cells {
        for (i, c) in row.iter().enumerate() {
            let w = UnicodeWidthStr::width(c.as_str());
            if w > widths[i] {
                widths[i] = w;
            }
        }
    }

    let mut out = String::new();
    let header: Vec<String> = s
        .columns
        .iter()
        .enumerate()
        .map(|(i, c)| pad(c, widths[i]))
        .collect();
    let _ = writeln!(out, " {}", header.join(" | ").trim_end());

    // Each column occupies width + one space of padding on each side, and the
    // columns are joined by '+' sitting where the '|' does.
    let sep: Vec<String> = widths.iter().map(|w| "-".repeat(w + 2)).collect();
    let _ = writeln!(out, "{}", sep.join("+"));

    for row in &cells {
        let line: Vec<String> = row.iter().enumerate().map(|(i, c)| pad(c, widths[i])).collect();
        let _ = writeln!(out, " {}", line.join(" | ").trim_end());
    }

    let _ = writeln!(
        out,
        "({} row{}{})",
        s.rows.len(),
        if s.rows.len() == 1 { "" } else { "s" },
        if s.truncated { ", truncated by max_rows" } else { "" }
    );
    out
}

fn pad(s: &str, width: usize) -> String {
    let w = UnicodeWidthStr::width(s);
    if w >= width {
        s.to_string()
    } else {
        format!("{}{}", s, " ".repeat(width - w))
    }
}

pub fn one_line(sql: &str) -> String {
    let s: String = sql.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.chars().count() > 100 {
        let t: String = s.chars().take(97).collect();
        format!("{t}...")
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ResultSet {
        ResultSet {
            columns: vec!["id".into(), "name".into()],
            rows: vec![
                vec![Some("1".into()), Some("alice".into())],
                vec![Some("2".into()), None],
            ],
            command: None,
            truncated: false,
            statement: "select id, name from t".into(),
        }
    }

    #[test]
    fn table_aligns_and_marks_nulls() {
        let out = render(&[sample()], Format::Table).unwrap();
        assert!(out.contains("id | name"));
        assert!(out.contains("NULL"));
        assert!(out.contains("(2 rows)"));
    }

    #[test]
    fn separator_lines_up_with_the_header() {
        let out = render(&[sample()], Format::Table).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        // The '+' in the rule must sit exactly under the '|' in the header.
        let bar = lines[0].find('|').unwrap();
        let plus = lines[1].find('+').unwrap();
        assert_eq!(bar, plus, "header:\n{}\nrule:\n{}", lines[0], lines[1]);
        // The rule spans the full grid; data lines are right-trimmed, so they
        // are never longer than it.
        assert!(lines[1].len() >= lines[0].len());
        assert!(lines[1].len() >= lines[2].len());
    }

    #[test]
    fn wide_values_widen_their_column() {
        let mut s = sample();
        s.rows[0][0] = Some("1234567890".into());
        let out = render(&[s], Format::Table).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0].find('|'), lines[1].find('+'));
    }

    #[test]
    fn json_uses_real_nulls() {
        let out = render(&[sample()], Format::Json).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["rows"][1]["name"], Value::Null);
        assert_eq!(v["row_count"], 2);
    }

    #[test]
    fn csv_quotes_when_needed() {
        let mut s = sample();
        s.rows[0][1] = Some("a,b\"c".into());
        let out = render(&[s], Format::Csv).unwrap();
        assert!(out.contains("\"a,b\"\"c\""));
    }

    #[test]
    fn truncation_is_reported() {
        let mut s = sample();
        s.truncated = true;
        assert!(render(&[s], Format::Table).unwrap().contains("truncated"));
    }
}
