---
title: Migrating Streamlit secrets
description: The credentials in .streamlit/secrets.toml move to the vault; st.secrets and streamlit run keep reading the file exactly as before.
---

# Streamlit (`.streamlit/secrets.toml`)

`.streamlit/secrets.toml` is Streamlit's own secrets file: the docs tell you
to put API keys and database passwords there, gitignore it, and read it
through `st.secrets`. It exists in two places - `<project>/.streamlit/`
alongside the app, and `~/.streamlit/` globally - and either way its entire
purpose is holding credentials in plaintext.

`jit migrate <project>` (category `streamlit`) finds a project's file;
`jit migrate ~/.streamlit/secrets.toml` or a home-wide run reaches the global
one. Credential lines move into the vault and the file is replaced with a
[live mount](../run/mounts.md) serving a template: table headers, connection
settings (`account`, `port`, `dialect`), comments and the original formatting
all pass through byte-for-byte. Only the credential values are filled in from
the vault, inside the line's own quotes, when a read is authorized.

Which lines count follows the same two signals `jit scan` uses: a value
matching a known vendor format (an `sk-proj-…` OpenAI key under any name),
or a secret-shaped key name (`password`, `db_password`, `api_key`) whose
value doesn't read as an ordinary setting.

## Using it after migration

**A project's file** is granted like any project mount - run the app through
jit from the project directory:

```sh
jit run -- streamlit run app.py
```

**The global `~/.streamlit/secrets.toml`** is a machine-wide credential file,
so it takes an explicit grant:

```sh
jit run --with streamlit -- streamlit run app.py
```

**Or just run it.** With per-process consent on (the default), run
`streamlit run` as normal and approve the Touch ID prompt naming the reader.

## What it looks like

Before:

```toml
OPENAI_API_KEY = "sk-proj-..."
db_password = "hunter2"

[connections.snowflake]
account = "ACME-PROD"
user = "analyst"
port = 443
password = "sn0wf@ll"
```

After, the file is a live mount rendering this template - three secrets in
the vault under the project's `streamlit-<project>` profile (or `streamlit`
for the global file):

```toml
OPENAI_API_KEY = "${OPENAI_API_KEY}"
db_password = "${DB_PASSWORD}"

[connections.snowflake]
account = "ACME-PROD"
user = "analyst"
port = 443
password = "${CONNECTIONS_SNOWFLAKE_PASSWORD}"
```

The variable name folds in the **table**, not just the key - every
connection's credential is literally named `password`, so without the table
two databases would collide on one vault path.

## Notes

- **Only provably-rewritable lines move.** A value in a multi-line string
  (`"""…"""`), one carrying escape sequences, or one sharing its line with a
  trailing comment stays in place - rewriting those can't be guaranteed to
  round-trip byte-for-byte, so the line keeps its `jit scan` finding instead.
  A file where **no** value is rewritable is reported by the scan as a
  manual fix with that reason, never as `jit migrate <path>` - scan asks
  migrate before promising (the same rule Kubernetes Secret manifests
  follow).
- **The two-part path gate is deliberate.** `secrets.toml` alone is a common
  name (a Rust config, a Helm values file); only `.streamlit/secrets.toml`
  is unambiguously Streamlit's. Name any other secrets.toml explicitly and
  it is handled as a [loose secret file](./index.md) instead.
- **Undo:** `jit migrate undo <path>` restores the original file
  byte-for-byte from its encrypted backup.
