---
title: The vault
description: Store, read, list, and delete secrets in the local encrypted vault.
---

# The vault

The vault is a local encrypted store at
`~/Library/Application Support/jitpass/` - each secret an individually
encrypted file, with the master key in your macOS login Keychain. Create it
once with `jit vault init` (part of the
[Quickstart](../getting-started/quickstart.md)).

Most secrets arrive through [`jit migrate`](../migrate/index.md) or
[`jit wrap`](../wrap/index.md), but the vault is directly usable too.

## Manage secrets by hand: `set` / `get` / `list` / `rm`

**Every command that reads, writes, or destroys a secret requires a fresh
Touch ID/passcode on each run** - `set`, `get`, `rm`, `import`, `restore`,
`clean`, `prune`, `orphans --prune`, `delete`, and `export`. These never ride
the background service's cached session: the prompt appears whether or not the
service is unlocked, so a process running as you can't read or destroy the
vault silently on an already-unlocked machine. Only `list`, `history`, and
`orphans` (without `--prune`) are prompt-free, because they expose names and
version timestamps, never a value.

`jit vault set myapp/NEW_KEY` prompts for a value and stores it (add `-f`
to overwrite an existing path, `--stdin` to pipe the value in);
`jit vault rm <path>...` deletes secrets (it confirms first). Several paths
delete under a **single** Touch ID gesture, so cleaning up a decommissioned
project is one approval rather than one per secret, and a bare group name (the
part before the slash in `jit vault list`) removes the whole group, with the
expansion announced and every path listed before you confirm. A missing path
is reported without stopping the rest. If a profile or a live mount still
points at a path, `rm` names it before the confirmation: deleting only the
secret leaves the mount serving a file nothing can fill, so for a migrated file
the right cleanup is
[`jit migrate remove <file>`](../migrate/undo-and-remove.md), which takes
the file, its profile and its secrets down together.
`jit vault get <path>` decrypts and prints one (`--copy` sends it to the
clipboard instead - marked so clipboard managers skip it, and auto-cleared
after 45 seconds unless you've copied something else by then); on a
terminal, a footer line follows on stderr with when the secret was
last updated and which profile uses it - piped output gets the value only.
`jit vault list` shows what's stored - names and paths only, never values.
On a terminal, entries group under a header per prefix, and each group
states where it came from and how recently it changed:

```
$ jit vault list
[myapp] 2 · dotenv · from ~/code/myapp/.env · 7d ago
    DATABASE_URL  STRIPE_API_KEY

[notion-sync] 1 · mcp · from ~/.mcp.json · 2d ago
    NOTION_API_KEY

3 secrets stored, plus 2 encrypted file backups kept for jit migrate undo (list with --all).
```

That header line is what tells two look-alike groups apart: `myapp` and
`myapp-2` holding the same key names are only a duplicate if they came
from the same file. A group whose members were migrated from different
files, or set by hand, says so instead (`set directly`), and a long path
is truncated rather than wrapped. When two groups do look like one file
stored twice, a note under the listing points at
[`jit vault duplicates`](./maintenance.md#jit-vault-duplicates---find-groups-that-hold-the-same-secrets),
which compares the actual values.

Piped or redirected, output stays one full path per line
(`myapp/DATABASE_URL`), so it feeds `grep` and scripts unchanged.
`-l` annotates each secret with its own class and age; `--by origin`
buckets by source file instead of by path.

With [shell completion](../getting-started/install.md#shell-completion)
installed, `jit vault get <TAB>` completes stored paths - names only, so
it never triggers a Touch ID prompt mid-keystroke.

## Changed an API key? Update the vault, not the file

After migration, the file on disk is no longer where a secret lives, so
when a provider issues you a new key, don't paste it into `.env`. Update
the vault value instead:

1. **Find the secret's path.** Open the `.env.pointers` file next to the
   mount, or run `jit status --secrets`; both map each variable to its
   vault path.
2. **Set the new value:**

   ```
   $ jit vault set myapp/STRIPE_API_KEY
   Enter value for myapp/STRIPE_API_KEY:
   myapp/STRIPE_API_KEY already exists in the vault. Overwrite it? The current value is kept as an archived version (`jit vault history myapp/STRIPE_API_KEY`). [y/N] y
   Stored myapp/STRIPE_API_KEY
   ```

No re-migration needed; everything downstream picks the new value up on
its next fetch:

- A live-mounted `.env`/`.npmrc` serves fresh vault content on every read,
  so the next granted read sees the new key.
- `jit run`, `jit export`, the AWS CLI/SDKs, and kubectl all resolve the
  vault on demand.
- Anything already *holding* the old value keeps it until restarted: a
  running dev server, an MCP server, or a shell that ran
  `eval "$(jit export ...)"` at startup. Restart the process (or open a
  new shell) and it picks up the new key.

## Botched a rotation? `history` / `restore`

Overwriting keeps the outgoing value as an encrypted archived version (the
newest 5 per secret). If the new key turns out to be wrong - pasted the
wrong thing, revoked the old one too soon - the old value is one command
away:

```
$ jit vault history myapp/STRIPE_API_KEY
1752655103906210000  archived 2m ago (2026-07-16 12:38:23), value from 2026-05-02

$ jit vault restore myapp/STRIPE_API_KEY
Restored myapp/STRIPE_API_KEY. The value it replaced is archived, `jit vault history myapp/STRIPE_API_KEY`.
```

`restore` takes a fresh Touch ID/passcode approval (changing what a secret
resolves to never happens silently), brings back the newest version by
default (`--version <stamp>` for an older one), and archives the value it
displaces - so flipping between two versions can never lose either.
`jit vault rm` deletes a secret's archived versions with it: rm means gone.

One special case: for a new **Terraform Cloud** token or **Docker
registry** login, just run [`terraform login`](../migrate/terraform.md)
or [`docker login`](../migrate/docker.md) again - migration wired each
tool's own credentials helper to jit, so the re-login lands directly in
the vault. A **[git HTTPS](../migrate/git.md)** push that re-authenticates
with a fresh password lands there the same way, through git's own
credential helper.

## More

- **[Back up and restore](./backup-restore.md)** - `vault export` /
  `vault import`, for disaster recovery
- **[Maintenance](./maintenance.md)** - `rekey` the master key, find
  copies of the same secret with `duplicates`, `prune` stale backups,
  delete secrets nothing references with `orphans`, `clean` out all
  secrets, or `delete` the vault entirely
