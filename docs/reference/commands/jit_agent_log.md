## jit agent log

Show the agent's own log (session events, mount reads, serve errors)

### Synopsis

Prints the tail of the agent's log file, the durable, timestamped record
of session events, mount reads (with who read them), and serve errors that
outlives the in-memory snapshot `jit agent status` reports.

The file lives alongside the vault as agent.log (the previous generation
is kept as agent.log.1 after rotation). This command exists because the
investigations that need the log are exactly the ones where hunting down
its path is one obstacle too many.

```
jit agent log [flags]
```

### Options

```
  -f, --follow      keep printing new lines as the agent writes them (Ctrl-C to stop)
  -n, --lines int   how many trailing lines to print (default 50)
```

### SEE ALSO

* [jit agent](jit_agent.md)	 - Run a background helper so you only unlock once, not once per command

