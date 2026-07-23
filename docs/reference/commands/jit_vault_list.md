## jit vault list

List stored secret paths (names only, never values)

### Synopsis

Lists every secret path currently stored, never a value. On a terminal,
secrets are grouped under a faint header per first path segment with a
count; piped or redirected, output stays one full path per line, so it
feeds grep and scripts unchanged. The encrypted file backups jit migrate
keeps for `jit migrate undo` are summarized in the count line rather than
listed; --all lists them too.

--by origin groups secrets by the source file they were migrated from
(--by group by the finer import-batch id); -l annotates each with its
class and age. --format json prints an object per secret carrying that
provenance, for grouping in a script without a `get` per secret.

```
jit vault list [flags]
```

### Options

```
      --all             also list jit migrate's encrypted file backups (_backups/...)
      --by string       group secrets by: "path" (default), "origin" (source file), or "group" (import batch) (default "path")
      --format string   output format: "text" (default) or "json" (default "text")
  -l, --long            show each secret's class and last-updated age (terminal output only)
```

### SEE ALSO

* [jit vault](jit_vault.md)	 - Manage the local encrypted secret vault

