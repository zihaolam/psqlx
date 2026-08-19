# psqlx

Policy-guarded Postgres access for AI agents.

You register a connection once. The password goes to the macOS keychain. Agents
then run:

```
psqlx query prod "select count(*) from users"
```

They never see a hostname, a username, or a password — and by default they
cannot change anything, because every query runs inside a read-only transaction
that is always rolled back.

## Install

```sh
cargo install --path .
```

The binary lands in `~/.cargo/bin/psqlx`.

## Setup (you do this once)

```sh
psqlx conn add
```

That walks you through it. Every secret is read at a hidden prompt, so nothing
sensitive lands in your shell history:

```
Connection name: prod

Enter the connection details, or paste a postgres:// URL.
Paste a connection URL? [y/N] y
Connection URL (hidden):
  Parsed: postgres://bot:****@127.0.0.1:15432/app?sslmode=disable
Description (optional): prod replica

  name      prod
  target    bot@127.0.0.1:15432/app
  sslmode   disable
  password  keychain (never printed back)
  policy    read-only

Save this connection? [Y/n]
Added connection 'prod' -> bot@127.0.0.1:15432/app
Testing connection... ok — PostgreSQL 15.5, as bot on app
```

Answer `n` to the URL question to enter host / port / database / user
individually, with the password at its own hidden prompt. Either way the
password goes to the keychain and the URL is echoed back redacted so you can
check the rest of it.

For scripted setup you can still pass flags, and anything you supply is simply
not prompted for:

```sh
psqlx conn add prod \
  --host 127.0.0.1 --port 15432 \
  --db app --user readonly_bot --sslmode disable
# still prompts (hidden) for just the password

# fully non-interactive
psqlx conn add prod --host ... --db app --user bot --password-stdin < pw.txt
psqlx conn add prod --host ... --db app --user bot --password-env PGPASSWORD_PROD
```

Avoid `--url 'postgres://user:pass@...'` on the command line — that does put the
password in your history. Use the hidden prompt instead.

If you tunnel to a bastion, open the tunnel yourself and point the connection at
the local end of it:

```sh
ssh -f -N -L 15432:db.internal:5432 bastion-prod
psqlx conn add prod --host 127.0.0.1 --port 15432 --db app --user readonly_bot
```

Then check it:

```sh
psqlx conn test prod
psqlx connection list
```

## What the agent runs

```sh
psqlx connection list                  # which connections exist
psqlx query prod "select 1"            # run SQL
psqlx query prod --format json "..."   # json | csv | markdown | table
psqlx tables prod                      # list tables and views
psqlx describe prod public.users       # columns, indexes, constraints
psqlx schemas prod
psqlx guide                            # instructions written for the agent
```

`psqlx guide` prints a short brief you can paste into `CLAUDE.md` or an agent's
system prompt.

## Read-only by default

Three independent layers have to be defeated for a write to land. The first is
the only one that produces nice error messages; the third is the one to actually
rely on.

**1. The parser.** psqlx tokenizes the SQL properly — dollar quotes, `E''`
strings, nested block comments and quoted identifiers all lex correctly — then
requires the statement verb to be one of `SELECT WITH TABLE VALUES SHOW EXPLAIN`.
It also rejects `INSERT/UPDATE/DELETE/MERGE/INTO` appearing anywhere (which is
how data-modifying CTEs and `SELECT ... FOR UPDATE` get caught), a list of
escape-hatch functions (`pg_read_file`, `dblink`, `pg_sleep`, `lo_export`,
`set_config`, …), and the credential catalogs (`pg_authid`, `pg_shadow`).

Because it is a real lexer rather than a substring match, `select 'delete from
users'`, `select deleted_at from update_log` and `select "insert" from t` are all
allowed — the write keywords there are strings and identifiers, not verbs.

Multiple statements are split and each one checked, so `select 1; drop table
users` is rejected.

Transaction control is blocked for the same reason: `COMMIT` in the middle of a
script would close the read-only transaction psqlx opened and leave the rest
running in autocommit read-write mode. Because the check is an allowlist rather
than a list of banned words, every spelling is covered — `COMMIT`, `END`,
`ABORT`, `BEGIN`, `START TRANSACTION`, `SAVEPOINT`, `SET SESSION CHARACTERISTICS`
— so `select 1; commit; insert into ...` never reaches the server at all.

**2. The transaction.** Everything runs inside `BEGIN TRANSACTION READ ONLY` and
is rolled back on every exit path. Postgres refuses writes in that transaction
itself, so anything the parser misses still fails. `select nextval('seq')` is a
good example: the parser lets it through, Postgres does not.

The session is pinned too: psqlx issues `SET SESSION
default_transaction_read_only = on` right after connecting, so even an implicit
transaction outside our explicit one is read-only. Undoing that needs `SET` or
`set_config()`, both of which layer 1 blocks.

Each transaction also sets `statement_timeout`, `lock_timeout` and
`idle_in_transaction_session_timeout`, so a runaway query cannot pin your primary.

**3. The database role.** This is the real boundary. Point the connection at a
role that only has `SELECT`:

```sql
CREATE ROLE readonly_bot LOGIN PASSWORD 'change-me';
GRANT CONNECT ON DATABASE app TO readonly_bot;
GRANT USAGE ON SCHEMA public TO readonly_bot;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly_bot;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO readonly_bot;
ALTER ROLE readonly_bot SET default_transaction_read_only = on;
```

## Policies

```sh
psqlx policy show prod
psqlx policy set prod --max-rows 500 --statement-timeout 10s
psqlx policy set prod --deny-table users --deny-table api_keys
```

| Setting | Default | Meaning |
| --- | --- | --- |
| `mode` | `read-only` | `read-only`, `read-write`, or `unrestricted` |
| `max_rows` | `1000` | Row cap per statement, applied as a server-side `LIMIT`. 0 = unlimited |
| `statement_timeout` | `30s` | Per-statement timeout |
| `lock_timeout` | `5s` | How long to wait on a lock before giving up |
| `max_statements` | `20` | Statements allowed in one `query` call |
| `deny_tables` | — | Reject any query referencing these identifiers |
| `allow_write_tables` | — | In read-write mode, restrict writes to these tables |

### Write modes

`read-write` additionally allows `INSERT/UPDATE/DELETE/MERGE` but never DDL.
Even then, **writes roll back unless the caller passes `--commit`** — so an agent
can dry-run a mutation and show you the row count before anything is durable.

```sh
psqlx policy set staging --mode read-write --allow-write-table staging_events
psqlx query staging "delete from staging_events where id = 1"   # rolled back
psqlx query staging --commit "delete from staging_events where id = 1"
```

`unrestricted` turns off the parser checks entirely. It exists so you are not
forced to keep a second tool around; do not point an agent at it.

## Audit log

Every attempt is appended to `~/.psqlx/audit.log` as JSON lines, including the
rejected ones — those are the interesting half.

```sh
psqlx audit -n 50
psqlx audit -n 200 | jq 'select(.verdict == "denied")'
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Connection failure, SQL error, or bad usage |
| 3 | The policy rejected the statement |

Agents can branch on 3 to tell "you're not allowed to do that" apart from "your
SQL was wrong".

## Files

```
~/.psqlx/config.toml    connections and policies, mode 0600, never any secrets
~/.psqlx/audit.log      JSONL query log, mode 0600
```

Passwords live in the macOS keychain under service `psqlx`, account
`<connection name>`. Alternatives if you'd rather not use the keychain:

```sh
psqlx conn add prod ... --password-env PGPASSWORD_PROD
psqlx conn add prod ... --password-command 'op read op://vault/db/password'
```

Set `PSQLX_HOME` to move the config directory, and `PSQLX_CONNECTION` to pick a
default connection per-shell.

## What this does and does not protect against

**It does** keep credentials out of the agent's context window, make destructive
statements impossible on a read-only connection, cap runaway queries, and leave
you an audit trail.

**It does not** stop a genuinely adversarial process running as your user. Such a
process could read `~/.psqlx/config.toml` or ask the keychain for the password
itself — psqlx is a guardrail, not a sandbox boundary. If that is your threat
model, the answer is a read-only Postgres role (layer 3 above), so that the
credentials the agent could steal are not worth stealing.

Two things worth doing regardless:

- Give the agent a read-only role, not your superuser.
- Deny the agent read access to the config directory, e.g. in Claude Code's
  `settings.json`: `"deny": ["Read(~/.psqlx/**)"]`.
