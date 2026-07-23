## jit vault clean

Delete every secret in the vault (the vault itself stays set up)

### Synopsis

Permanently deletes every secret stored in the vault, including the
encrypted file backups jit migrate keeps for `jit migrate undo`, after
this, undo has nothing left to restore from. The vault itself stays
initialized (its encryption key and device identity are kept), so
`jit vault set`/`jit migrate` keep working immediately afterward.
Refuses while any file is still live-mounted, unmount first, or the
mounted file's real content would be gone for good.
To destroy the vault entirely, key included, use `jit vault delete`.

```
jit vault clean [flags]
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

