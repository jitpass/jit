## jit vault rm

Delete one or more secrets

### Synopsis

Permanently deletes the secret at each <path>. Beyond the [y/N]
confirmation, a fresh Touch ID/passcode is required (never the cached
service session), so a process running as you can't delete a secret
without a live human gesture even while the vault is unlocked.

Multiple paths delete in one call under a SINGLE gesture, so cleaning up
a batch (a test run, a decommissioned project) is one approval, not one
per secret. Missing paths are reported but don't stop the rest; the
command exits non-zero if any path couldn't be removed.

-y/--yes skips the typed confirmation (never the fingerprint), matching
every other jit command. `-f`/`--force` is still accepted as a synonym,
so the `rm -f` reflex keeps working.

```
jit vault rm <path>... [flags]
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

