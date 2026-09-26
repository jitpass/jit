## jit vault import

Restore secrets from a jit vault export file

### Synopsis

Decrypts <file> (written by `jit vault export`) with the passphrase you
supply and writes every secret it contains into this vault, overwriting
any existing secret at the same path. Confirms first unless --yes, the
passphrase prompt only comes after that, so declining never costs a
wasted attempt at typing it.

After the vault's Secure Enclave key was lost, importing is how secrets
come back, and jit tracks which ones still can't be opened. If it can't
check (its record of them is unreadable), --finish stops tracking once
you've imported every recovery file you have: it lists the secrets that
may still not open, confirms unless --yes, and keeps the lost key's
files under a dated name. It takes no file and needs no Touch ID.

```
jit vault import <file> [flags]
```

### Examples

```
  jit vault import ~/jit-recovery.json
  jit vault import --finish    # after a lost key, once every recovery file is in
```

### Options

```
      --finish   after a lost key: stop tracking a restore jit can't check, once every recovery file is imported
      --stdin    read the passphrase from stdin instead of prompting
  -y, --yes      skip the confirmation prompt and import immediately
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit vault](jit_vault.md)	 - Manage the local encrypted secret vault

