## jit profile drop

Remove variables from a profile manifest

### Synopsis

Removes variables from a profile manifest, keeping the rest. Use it
for an entry the tool does not actually need — the leftovers a
restored or merged manifest carries, which `jit doctor` reports as
[missing] because the vault has no value for them.

It refuses to drop a variable whose vault path holds a value: that
entry is live, and dropping it would leave a real secret with
nothing pointing at it (`jit vault rm` is the command that means
that). It refuses to empty a manifest, and it never touches a
secret, a mount or another profile.

A `.pointers` companion left beside a live mount by an older jit is
rewritten to match; none is created.

No value is read, so no Touch ID is needed.

```
jit profile drop <name> VAR... [flags]
```

### Examples

```
  jit profile drop hibob HIBOB_BASE_URL
  jit profile drop hibob HIBOB_BASE_URL HIBOB_FIELDS --dry-run
```

### Options

```
      --dry-run   show what would be dropped; change nothing
  -y, --yes       skip the confirmation prompt
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit profile](jit_profile.md)	 - Write, edit, and delete profile manifests

