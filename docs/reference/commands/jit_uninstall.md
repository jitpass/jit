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
By itself it does NOT put migrated files back.

Add --restore for the whole way out: every file jit migrated on this Mac
gets its secrets back as plaintext first, then the purge runs. Live mounts,
pointer files and MCP configs are written from the CURRENT vault values; a
shell config has jit's export line turned back into export lines, in place,
so nothing you added since is lost; any other file gets its content from
before jit, and when it changed since, today's version is kept beside it as
<name>.before-jitpass-removal. Shell history and AI caches stay cleaned,
and a migrated file you have since deleted is not recreated. If even one
file cannot be put back, nothing is deleted and the exit code is 2.
`--restore --dry-run` shows the plan, including the secrets that have no
file to go back to; `jit vault export <file>` first keeps those.

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

### Examples

```
  jit uninstall                       # the software; the vault stays
  jit uninstall --purge               # and everything jit stored
  jit uninstall --restore --dry-run   # what putting every file back would do
  jit uninstall --restore             # files back as plaintext, then nothing left
```

### Options

```
      --dry-run         print the plan and change nothing (no Touch ID)
      --format string   output format: "text" (default), "json" (with --dry-run: the plan) or "ndjson" (one event per step, for a program driving this) (default "text")
      --keep-binary     leave the jit binary in place (e.g. it's managed by a package manager)
      --purge           also erase the vault and global config (destroys your secrets)
      --restore         first put every file jit migrated back as plaintext, across this Mac; then --purge. One file that cannot be put back stops it with nothing deleted
  -y, --yes             skip the typed y/N confirmation (still requires the Touch ID/passcode gate)
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

