## jit vault export

Export every secret to a passphrase-encrypted local backup file

### Synopsis

Decrypts every secret currently in the vault and re-encrypts the whole set
under a passphrase you supply, NOT the vault's own per-secret encryption,
which is bound to this device and useless on a different machine. A
passphrase-derived key is what actually makes this file restorable after
laptop loss or a reformat, `jit vault import <file>` reverses it, on this
machine or any other. Remembering the passphrase is entirely on you: jit
never stores it anywhere. This is a local file, moved around by whatever
means you choose, jit never uploads it.

--stdin reads the passphrase from stdin (one line, no confirmation
double-entry) instead of the default hidden prompt, for scripting, e.g.
piping one in from a password manager's own CLI.

```
jit vault export <file> [flags]
```

### Options

```
      --stdin   read the passphrase from stdin instead of prompting (no confirmation double-entry)
```

### SEE ALSO

* [jit vault](jit_vault.md)	 - Manage the local encrypted secret vault

