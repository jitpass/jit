## jit mount relocate

Re-point a mount registration at the project's new location

### Synopsis

Updates the registry entries for a project that has been renamed or
moved, so its mounted files are served where they now are.

The project must carry a jit record (written by `jit migrate`) naming
the mounts it has. Only entries whose recorded path is GONE are
re-pointed: a registration that still resolves is left alone, so this
can never steal a live mount from another project.

No secret is read, so no Touch ID is needed.

```
jit mount relocate <project dir> [flags]
```

### Examples

```
  jit mount relocate ~/work/hibob
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

