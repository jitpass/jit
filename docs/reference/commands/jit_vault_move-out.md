## jit vault move-out

Keep vault entries as plain settings beside the vault instead

### Synopsis

Move each named vault entry out of the vault into a plain setting beside it, and point
every profile that names it at the setting. The value does not change and files that read
it keep working, but any program on this Mac can then read it without Touch ID.

An AI job that gets the value is moved to the setting too, once the jit service has checked
the two copies match. One it can't check (an each-time job while the vault is locked) stops
until you approve it again, and the move prints the line that does.

For a value the scan counts as a secret, that leaves a secret in plain text, and jit scan
reports it again. Undo with jit vault move-in.

```
jit vault move-out <path>... [flags]
```

### Examples

```
  jit vault move-out billing-sync/EXPORT_SECRETS_FILE
```

### Options

```
      --format string   output format: "text" (default) or "json"; json needs --yes (default "text")
  -y, --yes             skip the confirmation question; Touch ID is still asked
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit vault](jit_vault.md)	 - Manage the local encrypted secret vault

