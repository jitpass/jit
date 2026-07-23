## jit service log

Show the service's raw operational output (startup, mount notes, serve errors)

### Synopsis

Prints the tail of the service's raw output log: the timestamped operational
lines the daemon prints as it runs, startup and shutdown, mount notes (with
who read them), serve-error detail, and anything a crash leaves behind.

This is the low-level debug view, not the audit trail. The session events
themselves, every unlock, denial, lock, use, and refused peer, live in the
structured trail that `jit audit` reads, filters, and follows; they are no
longer duplicated as prose here. Reach for `jit audit` for "what happened and
who did it", and for this when a serve error or a startup problem needs its
raw context.

The file lives alongside the vault as agent.log (the previous generation
is kept as agent.log.1 after rotation). This command exists because the
investigations that need the log are exactly the ones where hunting down
its path is one obstacle too many.

```
jit service log [flags]
```

### Options

```
  -f, --follow      keep printing new lines as the service writes them (Ctrl-C to stop)
  -n, --lines int   how many trailing lines to print (default 50)
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit service](jit_service.md)	 - Manage jit's background service (the daemon that holds your session and serves mounts)

