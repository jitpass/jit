---
title: Migrating ~/.pypirc
description: PyPI upload tokens and private-index passwords move to the vault; twine, uv, and poetry keep reading the file exactly as before.
---

# PyPI (`~/.pypirc`)

`~/.pypirc` is where twine, `uv publish`, poetry and setuptools read the
credentials they upload releases with - a PyPI API token (`pypi-…`), and often
a password for a private company index alongside it. Every one sits in
plaintext, usually with `chmod 600` as its only protection.

This is a **publish** credential, which is what makes it worth moving: with it
an attacker ships a new version of any project the account owns, straight into
other people's installs. Same blast radius as the npm and cargo registry
tokens, and the same reason it rates High in [`jit scan`](../audit/index.md).

`jit migrate ~/.pypirc` (category `pypirc`) moves every repository section's
`password` into the vault and replaces `~/.pypirc` with a
[live mount](../run/mounts.md) serving a template: the `[distutils]`
index-servers list, `repository` URLs, `username` lines, comments, blank lines
and the original spacing around `=` all pass through byte-for-byte. Only the
password values are filled in from the vault, and only when a read is
authorized: with per-process consent on (the default), by approving the Touch
ID prompt when a tool reads the file, or explicitly with
`jit run --with pypi` (for scripts and CI, or a hard gate).

`username` is left alone deliberately. For a token login it is the literal
`__token__`, and even for a password login the username is not the secret.

## Using it after migration

**Grant a run the real file:**

```sh
jit run --with pypi -- twine upload dist/*
jit run --with pypi -- uv publish
jit run --with pypi -- poetry publish
```

The grant is scoped to that run's process tree and gone the moment it exits.
These tools read the file directly, so (unlike an env-var secret) there's no
"inject it into the environment" shortcut.

To keep typing the command directly, `jit wrap add twine --grant pypi`
installs a shim that grants the file per invocation.

**Or just run it.** With per-process consent on (the default), run `twine
upload` as normal and approve the Touch ID prompt naming the reader.

## What it looks like

Before:

```ini
[distutils]
index-servers =
    pypi
    internal

[pypi]
username = __token__
password = pypi-AgEIcHlwaS5vcmcCJDk0YTUxZmE0…

[internal]
repository = https://pypi.internal.example/simple
username = ci-publisher
password = hunter2
```

After, the file is a live mount rendering this template - two secrets in the
vault at `pypirc/PYPI_PASSWORD` and `pypirc/INTERNAL_PASSWORD`:

```ini
[distutils]
index-servers =
    pypi
    internal

[pypi]
username = __token__
password = ${PYPI_PASSWORD}

[internal]
repository = https://pypi.internal.example/simple
username = ci-publisher
password = ${INTERNAL_PASSWORD}
```

The variable name folds in the **section**, not just the key - every section's
credential is literally named `password`, so without the section two
repositories would collide on one vault path.

## Notes

- **Environment-variable credentials are a different category.** Poetry and uv
  also accept `POETRY_HTTP_BASIC_<REPO>_PASSWORD` and
  `UV_INDEX_<NAME>_PASSWORD` straight from the environment, which is how they
  usually end up as plaintext exports in `~/.zshrc`. Those are
  [shell config](./shell-configs.md) territory: `jit migrate ~/.zshrc`.
- **Only `$HOME/.pypirc` is handled.** That is the path
  [packaging.python.org](https://packaging.python.org/en/latest/specifications/pypirc/)
  specifies and the one every tool reads by default. A `--config-file`
  override pointing elsewhere isn't discovered - name that file explicitly and
  it is handled as a [loose secret file](./index.md) instead.
- **Undo:** `jit migrate undo ~/.pypirc` restores the original file
  byte-for-byte from its encrypted backup.
