## jit vault import

Restore secrets from a jit vault export file

### Synopsis

Decrypts <file> (written by `jit vault export`) with the passphrase you
supply and writes every secret it contains into this vault, overwriting
any existing secret at the same path. Confirms first unless --yes — the
passphrase prompt only comes after that, so declining never costs a
wasted attempt at typing it.

```
jit vault import <file> [flags]
```

### Options

```
      --stdin   read the passphrase from stdin instead of prompting
  -y, --yes     skip the confirmation prompt and import immediately
```

### SEE ALSO

* [jit vault](jit_vault.md)	 - Manage the local encrypted secret vault

