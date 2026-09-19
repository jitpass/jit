## jit mount record

Write the project record for mounts already registered

### Synopsis

Writes each registered mount into its own project's record, so jit can
recognise that project if the folder is later renamed, moved or copied.

`jit migrate` writes this record for anything it mounts, so this is only
needed once, for mounts migrated before records existed. Mounts that
already have one are left alone, and a mount served from the global
profile store is skipped: "the project moved" is not a thing that
happens to your home directory.

It writes only inside the projects that already own these mounts, and
changes no registry entry, no manifest and no secret. No Touch ID.

```
jit mount record [flags]
```

### Examples

```
  jit mount record
```

### Options

```
  -y, --yes   skip the confirmation prompt
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit mount](jit_mount.md)	 - Re-point or register a project's live mounts

