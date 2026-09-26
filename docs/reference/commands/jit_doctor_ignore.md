## jit doctor ignore

Stop counting a doctor finding you have decided to leave as it is

### Synopsis

Takes findings out of `jit doctor`'s counts: an ignored finding no longer
fails the run, flips ok or trips --strict, and the report folds it into one
[ignored] line at the end (--show-ignored lists them). Nothing is fixed: a
problem you ignore is still broken, doctor just stops counting it.

A name is what a row leads with: a profile (aws-dev, mcp-github), a file
(~/.clisso.yaml, ~/ or absolute), or, for a section whose rows have no
name of their own, the section (backup, orphan, storage-format). All of a
profile's rows in one section are one finding. A name in more than one
section needs --kind: the section, or its JSON kind (config-deleted or
config_deleted). `jit doctor --format json` gives every finding's kind
and name, and the argv that ignores it.

Each ignore remembers what the finding said. When that changes (its
~/.aws/config entry is edited, another secret goes missing) the finding
comes back and counts again, marked as changed, until you ignore it again.

Ignores are kept in ~/.jit/doctor-ignore.json. Only ignore and unignore
write it; doctor itself never does. With --format json it prints
{ignored, unignored, error}, with the same exit codes.

```
jit doctor ignore <name>... [flags]
```

### Examples

```
  jit doctor ignore aws-dev aws-admin
  jit doctor ignore --kind config-deleted mcp-github-server
  jit doctor ignore --format json backup
```

### Options

```
      --format string   output format: "text" (default) or "json" (default "text")
      --kind string     the section the name is in, when it is in more than one (config-deleted, or the JSON kind)
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit doctor](jit_doctor.md)	 - One-shot health check: profiles, secrets, service, backup, and wrap shims

