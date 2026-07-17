## jit vault list

List stored secret paths (names only, never values)

### Synopsis

Lists every secret path currently stored, never a value. On a terminal,
secrets are grouped under a faint header per first path segment with a
count; piped or redirected, output stays one full path per line, so it
feeds grep and scripts unchanged. The encrypted file backups jit migrate
keeps for `jit migrate undo` are summarized in the count line rather than
listed; --all lists them too. --format json prints
{"secrets": [...], "backups": [...]} instead of one path per line.

```
jit vault list [flags]
```

### Options

```
      --all             also list jit migrate's encrypted file backups (_backups/...)
      --format string   output format: "text" (default) or "json" (default "text")
```

### SEE ALSO

* [jit vault](jit_vault.md)	 - Manage the local encrypted secret vault

