## jit vault set

Encrypt and store a secret

### Synopsis

Stores a secret at <path> (e.g. "stripe/dev-key"). If [value] is omitted,
prompts for it with hidden input. Use --stdin for scripts. Passing the value
as a bare argument works but lands in shell history, prefer the prompt or --stdin.

Requires a fresh Touch ID/passcode on every run, never the cached service
session, so writing a secret always takes a live human gesture.

```
jit vault set <path> [value] [flags]
```

### Options

```
  -f, --force   overwrite an existing secret without confirmation
      --stdin   read the secret value from stdin instead of prompting
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit vault](jit_vault.md)	 - Manage the local encrypted secret vault

