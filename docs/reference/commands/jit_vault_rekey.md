## jit vault rekey

Rotate the vault's master key, or move it into the Secure Enclave

### Synopsis

Does one of two things to the vault's master key.

Without --wrapper, it rotates the key.
It generates a new master key,
re-wraps every stored secret's key under it
(live secrets, file backups and archived versions;
the encrypted values themselves are never touched),
then replaces the old master key.
One Touch ID/passcode approval covers the whole operation.
Run it if the old key may have been exposed, or on a schedule;
otherwise the master key never changes for the vault's whole life.

A rotation is safe to interrupt: until the last step both keys exist,
every re-wrapped secret is verified before it's written,
and running `jit vault rekey` again finishes it.
Other vault commands refuse to write while one is in progress.

With --wrapper, it moves the key and doesn't change it.
Nothing is re-encrypted, and your grants and AI jobs keep working;
their own keys follow the next time the jit service starts.
--wrapper secure-enclave moves the key from your login keychain
into this Mac's Secure Enclave.
There, only JitPass can use it, after Touch ID or your password,
and no other program running as you can read it.
--wrapper keychain moves it back.

Before a move into the Secure Enclave,
save a recovery file with `jit vault export <file>`;
jit refuses the move until one is newer than your newest secret.
After the move the key can't leave this Mac:
if the Mac is lost, replaced or erased,
that file is how your secrets come back.
A move works only from the jit inside JitPass.app;
any other copy of jit is refused.
In the app, Settings › Protection makes the same move.
An interrupted move finishes when you run the same command again.

```
jit vault rekey [flags]
```

### Examples

```
  jit vault rekey                              # rotate the master key
  jit vault export ~/jit-recovery.json         # a recovery file, before a move
  jit vault rekey --wrapper secure-enclave     # move the key into the Secure Enclave
  jit vault rekey --wrapper keychain           # move it back to the keychain
```

### Options

```
      --wrapper string   move the key instead of rotating it: "secure-enclave" or "keychain"
  -y, --yes              skip the confirmation prompt
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit vault](jit_vault.md)	 - Manage the local encrypted secret vault

