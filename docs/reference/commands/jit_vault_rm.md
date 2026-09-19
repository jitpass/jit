## jit vault rm

Delete one or more secrets

### Synopsis

Permanently deletes the secret at each <path>. Beyond the [y/N]
confirmation, a fresh Touch ID/passcode is required (never the cached
service session), so a process running as you can't delete a secret
without a live human gesture even while the vault is unlocked.

Multiple paths delete in one call under a SINGLE gesture, so cleaning up
a batch (a test run, a decommissioned project) is one approval, not one
per secret. Missing paths are reported but don't stop the rest; the
command exits non-zero if any path couldn't be removed.

A bare group name (the part before the slash in `jit vault list`)
deletes every secret in that group: the expansion is announced and the
confirmation lists each path, still one gesture for the lot.

A secret something still uses is refused, and nothing is deleted: a
profile in any store jit can find (this directory's, the global one,
or any project under your home folder), a mount, or a pointer file such
as ~/.clisso.yaml. A profile missing a secret can't start its tool at
all, and rm deletes the version history too. --break-profiles deletes
anyway, after the same warnings, confirmation and Touch ID. If jit can't
read one of those files, it can't tell, and refuses the same way.

--dry-run shows what would be deleted and what uses it, then stops: no
prompt, no Touch ID. With --format json it prints paths, missing,
in_use and refused, for a script or app to confirm against.

-y/--yes skips the typed confirmation (never the fingerprint), matching
every other jit command, and never implies --break-profiles.
`-f`/`--force` is still accepted as a synonym for --yes, so the
`rm -f` reflex keeps working.

```
jit vault rm <path>... [flags]
```

### Examples

```
  jit vault rm stripe/dev-key
  jit vault rm old-proj/API_KEY old-proj/DB_URL   # one approval, both gone
  jit vault rm old-proj                           # the whole group, listed before you confirm
  jit vault rm --dry-run --format json old-proj   # what it would delete, and what uses it
```

### Options

```
      --break-profiles   delete secrets a profile or pointer file still uses
      --dry-run          show what would be deleted and what uses it; change nothing
      --format string    dry-run output format: "text" (default) or "json" (default "text")
  -y, --yes              skip the confirmation prompt
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit vault](jit_vault.md)	 - Manage the local encrypted secret vault

