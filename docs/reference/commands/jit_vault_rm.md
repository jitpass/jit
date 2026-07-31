## jit vault rm

Delete a secret

### Synopsis

Permanently deletes the secret at <path>. Beyond the [y/N] confirmation,
a fresh Touch ID/passcode is required (never the cached service session),
so a process running as you can't delete a secret without a live human
gesture even while the vault is unlocked.

-y/--yes skips the typed confirmation (never the fingerprint), matching
every other jit command. `-f`/`--force` is still accepted as a synonym,
so the `rm -f` reflex keeps working.

```
jit vault rm <path> [flags]
```

### Options

```
  -y, --yes   skip the confirmation prompt
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit vault](jit_vault.md)	 - Manage the local encrypted secret vault

