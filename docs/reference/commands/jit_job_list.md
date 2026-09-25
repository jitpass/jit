## jit job list

Show the approved AI jobs and whether each can run

### Synopsis

List every AI job: what it runs, whether it can run now, and who ran it
last. A job whose files changed, or whose secret was rotated, is marked
and cannot run until you approve it again. Reading this never prompts.

```
jit job list [flags]
```

### Options

```
      --format string   output format: text or json (default "text")
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit job](jit_job.md)	 - Let AI tools run approved scripts without seeing their keys

