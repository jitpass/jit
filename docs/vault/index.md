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

`jit vault set myapp/NEW_KEY` prompts for a value and stores it (add `-f`
to overwrite an existing path, `--stdin` to pipe the value in);
`jit vault rm <path>` deletes one secret (it confirms first).
`jit vault get <path>` decrypts and prints one (`--copy` sends it to the
clipboard instead). `jit vault list` shows what's stored - names and paths
only, never values - one path per line, so it pipes cleanly into `grep`:

```
$ jit vault list
myapp/DATABASE_URL
myapp/STRIPE_API_KEY
notion-sync/NOTION_API_KEY

3 secret(s) stored, plus 2 encrypted file backup(s) kept for `jit migrate undo` (list with --all).
```

With [shell completion](../getting-started/install.md#shell-completion)
installed, `jit vault get <TAB>` completes stored paths - names only, so
it never triggers a Touch ID prompt mid-keystroke.

## Changed an API key? Update the vault, not the file

After migration, the file on disk is no longer where a secret lives, so
when a provider issues you a new key, don't paste it into `.env`. Update
the vault value instead:

1. **Find the secret's path.** Open the `.env.pointers` file next to the
   mount, or run `jit profile show <name>`; both map each variable to its
   vault path.
2. **Set the new value:**

   ```
   $ jit vault set myapp/STRIPE_API_KEY
   Enter value for myapp/STRIPE_API_KEY:
   myapp/STRIPE_API_KEY already exists in the vault. Overwrite it? The current value can't be recovered afterward. [y/N] y
   Stored myapp/STRIPE_API_KEY
   ```

No re-migration needed; everything downstream picks the new value up on
its next fetch:

- A live-mounted `.env`/`.npmrc` serves fresh vault content on every read,
  so the next revealed read sees the new key.
- `jit run`, `jit export`, the AWS CLI/SDKs, and kubectl all resolve the
  vault on demand.
- Anything already *holding* the old value keeps it until restarted: a
  running dev server, an MCP server, or a shell that ran
  `eval "$(jit export ...)"` at startup. Restart the process (or open a
  new shell) and it picks up the new key.

One special case: for a new **Terraform Cloud** token, just run
`terraform login` again - [migration wired terraform's credentials helper
to jit](../migrate/terraform.md), so the re-login lands directly in the
vault.

## More

- **[Back up and restore](./backup-restore.md)** - `vault export` /
  `vault import`, for disaster recovery
- **[Maintenance](./maintenance.md)** - `prune` stale backups, `clean` out
  all secrets, or `delete` the vault entirely
