## jit uninstall

Remove jit's service, shims, and binary (keeps your vault unless --purge)

### Synopsis

Removes jit from this Mac: stops and unloads the background service, deletes
the wrap shims, and removes the jit binary (prompts for sudo only if its path
isn't writable). 

Your vault is NOT touched by default — jit is the only thing that can decrypt
it on this Mac, so uninstall leaves your secrets in place and tells you where
they are. Add --purge to also erase the vault and global config; uninstall
will name how many secrets that destroys and recommend `jit vault export`
first.

Uninstalling requires a fresh Touch ID/passcode approval — so someone at your
unlocked Mac can't remove jit (or --purge your secrets) without your presence.
--yes skips only the typed y/N confirmation, never the fingerprint. (This
guards the `jit uninstall` path; it is not a substitute for file permissions —
anyone with your shell can still delete files directly.)

```
jit uninstall [flags]
```

### Options

```
      --keep-binary   leave the jit binary in place (e.g. it's managed by a package manager)
      --purge         also erase the vault and global config (destroys your secrets)
  -y, --yes           skip the typed y/N confirmation (still requires the Touch ID/passcode gate)
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

