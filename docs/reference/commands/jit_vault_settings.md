## jit vault settings

List the plain settings kept beside the vault, with their values

### Synopsis

List the plain settings jit keeps beside the vault: the lines of a protected .env the
scan does not count as secrets (URLs, IDs, file names, flags). They are plain text,
readable without Touch ID. jit vault move-in puts one in the vault.

```
jit vault settings [flags]
```

### Options

```
      --format string   output format: "text" (default) or "json" (default "text")
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit vault](jit_vault.md)	 - Manage the local encrypted secret vault

