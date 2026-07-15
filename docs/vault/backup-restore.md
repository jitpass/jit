---
title: Back up and restore the vault
description: jit vault export writes a passphrase-encrypted backup file; import restores it.
---

# Back up and restore - `jit vault export` / `import`

For disaster recovery (laptop loss, a reformat), not a sync mechanism:

```
$ jit vault export ~/backup.json
Enter a passphrase to encrypt this export: ********
Confirm passphrase: ********
Exported 5 secret(s) to /Users/alex/backup.json.
```

The vault's day-to-day encryption is bound to this machine's keychain and
useless anywhere else, so the export derives its key from the passphrase
you type (Argon2id). That passphrase is the only way back in; jit never
stores it, on purpose - pick one you can recover, and keep the export file
somewhere that survives the laptop.

Restore with:

```
$ jit vault import ~/backup.json
```

Both commands take `--stdin` to read the passphrase from a pipe for
scripted backups; `import` confirms before writing (skip with `-y`).
