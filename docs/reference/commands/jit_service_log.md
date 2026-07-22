## jit service log

Show the service's own log (session events, mount reads, serve errors)

### Synopsis

Prints the tail of the service's log file, the durable, timestamped record
of session events, mount reads (with who read them), and serve errors that
outlives the in-memory snapshot `jit service status` reports.

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

### SEE ALSO

* [jit service](jit_service.md)	 - Manage jit's background service (the daemon that holds your session and serves mounts)

