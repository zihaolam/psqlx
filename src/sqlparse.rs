//! A small PostgreSQL lexer, good enough to split a script into statements and
//! classify each one.
//!
//! We deliberately do *not* build a full AST. The policy layer only needs to
//! know (a) where statement boundaries are, and (b) which bare keywords and
//! function calls appear outside of string literals, comments and quoted
//! identifiers. Getting those three "outside of" cases right is the whole job,
//! because they are exactly where a naive `contains("insert")` check gets
//! fooled.

use anyhow::{Result, bail};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    /// A bare (unquoted) word, lowercased. Keywords and identifiers alike.
    Word(String),
    /// A `"quoted identifier"`. Never treated as a keyword.
    QuotedIdent(String),
    /// Any string literal: `'...'`, `E'...'`, `$tag$...$tag$`.
    Str,
    Num,
    Punct(char),
}

#[derive(Debug, Clone)]
pub struct Statement {
    /// The statement text, trimmed, with the trailing `;` removed.
    pub sql: String,
    pub toks: Vec<Tok>,
}

impl Statement {
    /// First bare word, lowercased (the statement verb).
    pub fn verb(&self) -> Option<&str> {
        self.toks.iter().find_map(|t| match t {
            Tok::Word(w) => Some(w.as_str()),
            _ => None,
        })
    }

    /// Does any bare word equal `needle`?
    pub fn has_word(&self, needle: &str) -> bool {
        self.toks
            .iter()
            .any(|t| matches!(t, Tok::Word(w) if w == needle))
    }

    /// Identifiers immediately followed by `(` — i.e. function calls, lowercased.
    ///
    /// Both bare words *and* quoted identifiers count: PostgreSQL folds an
    /// unquoted name to lower case and treats `"dblink"(...)` as the very same
    /// function as `dblink(...)`. If we only looked at bare words, quoting the
    /// name — `select "dblink"(...)`, `select "pg_read_file"(...)` — would slip
    /// the call straight past the denied-function list. We lower-case the quoted
    /// form too so the match is fail-closed, exactly as `identifiers()` does.
    pub fn called_functions(&self) -> Vec<String> {
        let mut out = Vec::new();
        for pair in self.toks.windows(2) {
            if let Tok::Punct('(') = pair[1] {
                match &pair[0] {
                    Tok::Word(w) => out.push(w.clone()),
                    Tok::QuotedIdent(w) => out.push(w.to_ascii_lowercase()),
                    _ => {}
                }
            }
        }
        out
    }

    /// Every identifier-ish name in the statement, lowercased, bare and quoted
    /// alike. Used for `deny_tables` matching.
    pub fn identifiers(&self) -> Vec<String> {
        self.toks
            .iter()
            .filter_map(|t| match t {
                Tok::Word(w) => Some(w.clone()),
                Tok::QuotedIdent(w) => Some(w.to_ascii_lowercase()),
                _ => None,
            })
            .collect()
    }
}

/// Split a SQL script into statements, tokenizing as we go.
pub fn split(input: &str) -> Result<Vec<Statement>> {
    let chars: Vec<char> = input.chars().collect();
    let mut out = Vec::new();
    let mut toks: Vec<Tok> = Vec::new();
    let mut start = 0usize; // char index where the current statement began
    let mut i = 0usize;

    // Everything before the first real token is leading trivia, not part of the
    // statement text.
    let mut seen_token = false;

    macro_rules! push_stmt {
        ($end:expr) => {{
            if seen_token {
                let text: String = chars[start..$end].iter().collect();
                let text = text.trim().trim_end_matches(';').trim_end().to_string();
                if !text.is_empty() {
                    out.push(Statement {
                        sql: text,
                        toks: std::mem::take(&mut toks),
                    });
                }
            }
            toks.clear();
            seen_token = false;
        }};
    }

    while i < chars.len() {
        let c = chars[i];

        // --- whitespace ---
        if c.is_whitespace() {
            i += 1;
            continue;
        }

        // --- line comment ---
        if c == '-' && chars.get(i + 1) == Some(&'-') {
            i += 2;
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }

        // --- block comment (nestable in Postgres) ---
        if c == '/' && chars.get(i + 1) == Some(&'*') {
            let mut depth = 1;
            i += 2;
            while i < chars.len() && depth > 0 {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            if depth > 0 {
                bail!("unterminated block comment");
            }
            continue;
        }

        if !seen_token {
            start = i;
            seen_token = true;
        }

        // --- statement terminator ---
        if c == ';' {
            push_stmt!(i + 1);
            i += 1;
            continue;
        }

        // --- dollar-quoted string, or a $1 parameter ---
        if c == '$' {
            if let Some(end) = scan_dollar_quote(&chars, i) {
                toks.push(Tok::Str);
                i = end;
                continue;
            }
            // `$1`, `$$` handled above; anything else is punctuation.
            if chars.get(i + 1).is_some_and(|c| c.is_ascii_digit()) {
                i += 1;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
                toks.push(Tok::Num);
                continue;
            }
            toks.push(Tok::Punct('$'));
            i += 1;
            continue;
        }

        // --- string literal ---
        if c == '\'' {
            i = scan_quoted(&chars, i, '\'', false)?;
            toks.push(Tok::Str);
            continue;
        }

        // --- quoted identifier ---
        if c == '"' {
            let begin = i + 1;
            let end = scan_quoted(&chars, i, '"', false)?;
            // end is one past the closing quote
            let raw: String = chars[begin..end - 1].iter().collect();
            toks.push(Tok::QuotedIdent(raw.replace("\"\"", "\"")));
            i = end;
            continue;
        }

        // --- word, possibly a string-literal prefix (E'', B'', X'', U&'') ---
        if c.is_alphabetic() || c == '_' || (c as u32) > 127 {
            let begin = i;
            while i < chars.len() {
                let ch = chars[i];
                if ch.is_alphanumeric() || ch == '_' || ch == '$' || (ch as u32) > 127 {
                    i += 1;
                } else {
                    break;
                }
            }
            let word: String = chars[begin..i].iter().collect();
            let lower = word.to_ascii_lowercase();

            // E'...' / e'...' use backslash escapes; B/X are bit strings.
            if chars.get(i) == Some(&'\'') && matches!(lower.as_str(), "e" | "b" | "x" | "n") {
                i = scan_quoted(&chars, i, '\'', lower == "e")?;
                toks.push(Tok::Str);
                continue;
            }
            // U&'...' / U&"..."
            if lower == "u" && chars.get(i) == Some(&'&') {
                if chars.get(i + 1) == Some(&'\'') {
                    i = scan_quoted(&chars, i + 1, '\'', false)?;
                    toks.push(Tok::Str);
                    continue;
                }
                if chars.get(i + 1) == Some(&'"') {
                    let begin = i + 2;
                    let end = scan_quoted(&chars, i + 1, '"', false)?;
                    let raw: String = chars[begin..end - 1].iter().collect();
                    toks.push(Tok::QuotedIdent(raw.replace("\"\"", "\"")));
                    i = end;
                    continue;
                }
            }

            toks.push(Tok::Word(lower));
            continue;
        }

        // --- number ---
        if c.is_ascii_digit() {
            while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                i += 1;
            }
            // exponent / hex suffixes: consume trailing alphanumerics
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '.') {
                i += 1;
            }
            toks.push(Tok::Num);
            continue;
        }

        // --- anything else ---
        toks.push(Tok::Punct(c));
        i += 1;
    }

    push_stmt!(chars.len());
    let _ = seen_token; // the macro resets it; nothing reads it after the loop
    Ok(out)
}

/// Scan a `'`- or `"`-delimited literal starting at `start`. Returns the index
/// one past the closing delimiter. Handles doubled-delimiter escaping, plus
/// backslash escaping for `E'...'`.
fn scan_quoted(chars: &[char], start: usize, delim: char, backslash: bool) -> Result<usize> {
    let mut i = start + 1;
    while i < chars.len() {
        let c = chars[i];
        if backslash && c == '\\' {
            i += 2;
            continue;
        }
        if c == delim {
            if chars.get(i + 1) == Some(&delim) {
                i += 2; // '' escape
                continue;
            }
            return Ok(i + 1);
        }
        i += 1;
    }
    bail!(
        "unterminated {} literal",
        if delim == '\'' { "string" } else { "quoted identifier" }
    )
}

/// If a dollar-quoted string starts at `start`, return the index one past its
/// closing tag. Otherwise `None`.
fn scan_dollar_quote(chars: &[char], start: usize) -> Option<usize> {
    // $tag$ where tag is empty or [A-Za-z_][A-Za-z0-9_]*
    let mut j = start + 1;
    while j < chars.len() {
        let c = chars[j];
        if c == '$' {
            break;
        }
        let ok = if j == start + 1 {
            c.is_alphabetic() || c == '_' || (c as u32) > 127
        } else {
            c.is_alphanumeric() || c == '_' || (c as u32) > 127
        };
        if !ok {
            return None;
        }
        j += 1;
    }
    if j >= chars.len() || chars[j] != '$' {
        return None;
    }
    let tag: String = chars[start..=j].iter().collect(); // includes both $
    let tag_chars: Vec<char> = tag.chars().collect();

    let mut i = j + 1;
    while i < chars.len() {
        if chars[i] == '$' && i + tag_chars.len() <= chars.len() {
            if chars[i..i + tag_chars.len()] == tag_chars[..] {
                return Some(i + tag_chars.len());
            }
        }
        i += 1;
    }
    // Unterminated dollar quote: swallow the rest so we never leak its contents
    // into the token stream as keywords.
    Some(chars.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(sql: &str) -> Vec<String> {
        let s = split(sql).unwrap();
        s[0].toks
            .iter()
            .filter_map(|t| match t {
                Tok::Word(w) => Some(w.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn splits_on_semicolons() {
        let s = split("select 1; select 2;").unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].sql, "select 1");
        assert_eq!(s[1].sql, "select 2");
    }

    #[test]
    fn trailing_semicolon_optional() {
        let s = split("  select 1  ").unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].sql, "select 1");
    }

    #[test]
    fn semicolon_inside_string_is_not_a_boundary() {
        let s = split("select 'a;b'").unwrap();
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn keywords_inside_strings_are_invisible() {
        assert!(!words("select 'delete from users'").contains(&"delete".to_string()));
        assert!(!words("select $$ drop table x $$").contains(&"drop".to_string()));
        assert!(!words("select e'\\' delete '").contains(&"delete".to_string()));
    }

    #[test]
    fn quoted_identifiers_are_not_keywords() {
        let s = &split(r#"select "delete" from t"#).unwrap()[0];
        assert!(!s.has_word("delete"));
        assert!(s.identifiers().contains(&"delete".to_string()));
    }

    #[test]
    fn underscored_names_do_not_trip_keywords() {
        let w = words("select created_at, deleted_at, update_log.id from update_log");
        assert!(!w.contains(&"delete".to_string()));
        assert!(!w.contains(&"update".to_string()));
        assert!(!w.contains(&"create".to_string()));
    }

    #[test]
    fn comments_are_stripped() {
        let w = words("select 1 -- delete from users\n, 2 /* drop table t */");
        assert!(!w.contains(&"delete".to_string()));
        assert!(!w.contains(&"drop".to_string()));
    }

    #[test]
    fn nested_block_comments() {
        let w = words("select /* a /* b */ delete */ 1");
        assert!(!w.contains(&"delete".to_string()));
    }

    #[test]
    fn dollar_quote_with_tag() {
        let w = words("select $tag$ delete from t $tag$");
        assert!(!w.contains(&"delete".to_string()));
    }

    #[test]
    fn dollar_param_is_not_a_quote() {
        let s = &split("select * from t where id = $1 and x = 2").unwrap()[0];
        assert!(s.has_word("where"));
    }

    #[test]
    fn detects_function_calls() {
        let s = &split("select pg_sleep(10), now()").unwrap()[0];
        let f = s.called_functions();
        assert!(f.iter().any(|w| w == "pg_sleep"));
        assert!(f.iter().any(|w| w == "now"));
    }

    #[test]
    fn quoted_function_names_are_still_calls() {
        // PostgreSQL treats "dblink"(...) as the same function as dblink(...),
        // so a quoted name must not slip past the denied-function check.
        let s = &split(r#"select "dblink"('a','b'), "PG_SLEEP"(1)"#).unwrap()[0];
        let f = s.called_functions();
        assert!(f.iter().any(|w| w == "dblink"));
        assert!(f.iter().any(|w| w == "pg_sleep"));
    }

    #[test]
    fn verb_of_cte() {
        let s = &split("with x as (select 1) select * from x").unwrap()[0];
        assert_eq!(s.verb(), Some("with"));
    }
}
