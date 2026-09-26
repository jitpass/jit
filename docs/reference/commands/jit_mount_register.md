## jit mount register

Serve a project's mounts on this Mac

### Synopsis

Adds a project's mounted files to this Mac's registry, so the background
service serves them. Use it for a project that arrived by copy or clone:
the file comes with the folder, the registration never does, and until
this runs anything reading that file waits forever for a writer that
does not exist.

The project must carry a jit record (written by `jit migrate`) naming
the mounts it has, and each named file must already be there — this
creates nothing.

No secret is read, so no Touch ID is needed.

```
jit mount register <project dir> [flags]
```

### Examples

```
  jit mount register ~/code/billing
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

