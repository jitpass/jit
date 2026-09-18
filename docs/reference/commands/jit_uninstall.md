## jit uninstall

Remove jit's service, shims, and binary (keeps your vault unless --purge)

### Synopsis

Removes jit from this Mac: stops and unloads the background service, deletes
the wrap shims, and removes the jit binary (prompts for sudo only if its path
isn't writable). 

A copy of jit inside JitPass.app, or one Homebrew installed, is left where
it is: the app and brew own those, and uninstall says which to ask.

Your vault is NOT touched by default — jit is the only thing that can decrypt
it on this Mac, so uninstall leaves your secrets in place and tells you where
they are. Add --purge to also erase the vault and global config; uninstall
will name how many secrets that destroys and recommend `jit vault export`
first. A purge leaves nothing of jit's behind: the vault's key in the macOS
keychain, the history guard and its line in ~/.zshrc, the shim PATH line,
and the credential-helper scripts `jit migrate` installed all go with it.
It does NOT put migrated files back; run `jit migrate undo <path>` first.

Uninstalling requires a fresh Touch ID/passcode approval — so someone at your
unlocked Mac can't remove jit (or --purge your secrets) without your presence.
--yes skips only the typed y/N confirmation, never the fingerprint. (This
guards the `jit uninstall` path; it is not a substitute for file permissions —
anyone with your shell can still delete files directly.) When the vault's
key is already missing from the keychain, the same prompt runs without it,
so a vault nothing can open never blocks its own removal.

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

