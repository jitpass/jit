## jit vault restore

Bring back an archived previous version of a secret

### Synopsis

Replaces the secret's current value with an archived one from `jit vault
history`, the newest by default, or the one named by --version <stamp>.
The displaced current value is archived first, so a restore is itself
restorable and flipping between two versions can never lose either.

Restoring moves the archived encrypted file back into place byte-for-byte;
nothing is decrypted, but a fresh Touch ID/passcode approval is required,
changing what a secret resolves to must never happen silently.

```
jit vault restore <path> [flags]
```

### Options

```
      --version int   which archived version to restore, by its stamp from jit vault history (default: the newest)
```

### SEE ALSO

* [jit vault](jit_vault.md)	 - Manage the local encrypted secret vault

