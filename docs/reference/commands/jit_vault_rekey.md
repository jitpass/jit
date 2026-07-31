## jit vault rekey

Rotate the vault's master encryption key

### Synopsis

Generates a new master encryption key, re-wraps every stored secret's key
under it (live secrets, file backups, and archived versions, the encrypted
values themselves are never touched), then replaces the old master key.
One Touch ID/passcode approval covers the whole operation.

Run it if the old key may have been exposed, or simply on a schedule,
the vault's master key otherwise never changes for its whole life.

Safe to interrupt: until the very last step both keys exist, every
re-wrapped secret is verified before it's written, and re-running
`jit vault rekey` finishes an interrupted rotation. Other vault commands
refuse to write while one is in progress.

```
jit vault rekey [flags]
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

