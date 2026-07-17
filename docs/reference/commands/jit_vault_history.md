## jit vault history

List a secret's archived previous versions

### Synopsis

Every overwrite of a stored secret keeps the outgoing value as an encrypted
archived version (the newest 5 are kept). This lists them, never
decrypting anything, so it never prompts. `jit vault restore` brings one
back; `jit vault rm` deletes them along with the secret.

```
jit vault history <path> [flags]
```

### Options

```
      --format string   output format: "text" (default) or "json" (default "text")
```

### SEE ALSO

* [jit vault](jit_vault.md)	 - Manage the local encrypted secret vault

