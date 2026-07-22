## jit vault rm

Delete a secret

### Synopsis

Permanently deletes the secret at <path>. Beyond the [y/N] confirmation,
a fresh Touch ID/passcode is required (never the cached service session),
so a process running as you can't delete a secret without a live human
gesture even while the vault is unlocked.

```
jit vault rm <path> [flags]
```

### Options

```
  -f, --force   delete without confirmation
```

### SEE ALSO

* [jit vault](jit_vault.md)	 - Manage the local encrypted secret vault

