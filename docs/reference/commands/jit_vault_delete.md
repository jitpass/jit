## jit vault delete

Permanently destroy the whole vault, including its encryption key

### Synopsis

Destroys the entire vault: every secret, the encrypted file backups and
their undo index, the device identity, and the vault's encryption key in
the macOS keychain. Nothing on this machine can decrypt anything
afterward, only a passphrase-encrypted `jit vault export` file survives
(restorable later via `jit vault init` + `jit vault import`).

Refuses to run while any file is still live-mounted: unmount first
(`jit unmount <path>`), or the mounted file would be permanently stuck
serving placeholder values with its real content gone.

```
jit vault delete [flags]
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

