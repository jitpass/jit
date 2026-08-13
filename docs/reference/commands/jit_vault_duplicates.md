## jit vault duplicates

Report groups that hold the same secrets, and which are safe to retire

### Synopsis

Compares every stored secret's decrypted value in memory (no value is ever
printed or written) and reports two things `jit vault list` cannot know
from names alone:

  Duplicated groups: the same key names migrated from the same file, or
  from two copies of it (a re-migrated project, a copied workspace tree).
  When the values still match, the report names the copy that looks stale
  and the command that retires it cleanly: `jit migrate remove <file>`
  while the file still exists (it restores that file's plaintext, then
  deletes its profile and secrets), otherwise --prune or `jit vault rm`.
  Diverged copies (same file ancestry, different values now) are reported
  without a removal pick.

  Shared credentials: the same value stored by independent files, e.g.
  one API client used by five export scripts. These are NOT stale copies
  and there is nothing to fix, so they collapse to a count; --shared
  lists them with every place a rotation would have to reach.

Reporting only by default. --prune deletes the ONE shape that is pure
vault garbage: a stale copy whose origin file is already gone AND that no
profile jit can see references, after a [y/N] confirmation and a fresh
Touch ID/passcode. Everything else keeps its printed command instead, on
purpose: a copy whose file still exists has to be un-migrated by
`jit migrate remove` (which restores its plaintext, deregisters its mount
and drops its profile — deleting just the secrets would leave a mount
serving a file nothing can fill), a copy a profile still names is a
per-path `jit vault rm` decision, and diverged or shared copies are never
jit's call at all. --prune always reports what it left behind and why.

Reading every value means unlocking the vault and, for each credential
CLASS the per-process consent gate covers (aws, kube, git, shell_history,
...), approving that class once. A vault holding two gated classes
therefore asks about three times, not once: the unlock plus one per class.
`jit service consent off` removes the per-class half.

```
jit vault duplicates [flags]
```

### Examples

```
  jit vault duplicates
  jit vault duplicates --shared
  jit vault duplicates --prune
  jit vault duplicates --format json
```

### Options

```
      --format string   output format: "text" (default) or "json" (default "text")
      --prune           delete stale copies whose origin file is gone and which nothing references
      --shared          list the shared credentials instead of collapsing them to a count
  -y, --yes             skip the confirmation prompt (never the fingerprint)
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit vault](jit_vault.md)	 - Manage the local encrypted secret vault

