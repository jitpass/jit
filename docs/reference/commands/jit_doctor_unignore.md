## jit doctor unignore

Count an ignored doctor finding again

### Synopsis

Removes ignores `jit doctor ignore` recorded, so those findings show and
count again. A name removes every ignore by that name unless --kind
narrows it; --all removes them all. `jit doctor --show-ignored` lists what
is ignored. With --format json it prints {ignored, unignored, error}.

```
jit doctor unignore <name>... | --all [flags]
```

### Examples

```
  jit doctor unignore aws-dev
  jit doctor unignore --all
```

### Options

```
      --all             remove every ignore
      --format string   output format: "text" (default) or "json" (default "text")
      --kind string     only the ignores of this kind (config-deleted, or the JSON kind)
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit doctor](jit_doctor.md)	 - One-shot health check: profiles, secrets, service, backup, and wrap shims

