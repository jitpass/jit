## jit service status

Show whether the service is running, and whether its session is unlocked

### Synopsis

Reports whether jit's background service is running and, if so, whether its session is
unlocked. --format json prints a machine-readable snapshot instead of the
default text summary.

```
jit service status [flags]
```

### Options

```
      --format string   output format: "text" (default) or "json" (default "text")
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit service](jit_service.md)	 - Manage jit's background service (the daemon that holds your session and serves mounts)

