## jit agent history

List every unlock and lock this agent has seen, and what caused them

### Synopsis

Prints the agent's session history, most recent first: every Touch ID prompt
that succeeded (with the command that triggered it and what launched that
command) and every lock (with its cause — an idle timeout, or an explicit
`jit agent lock`).

This is the answer to "why does it keep asking me?" — a question the agent
previously had no way to answer, since only locks were ever recorded and the
unlocks that did the prompting left no trace at all.

In-memory and bounded, so a restart (launchd restarts the agent at every
login) empties it. The same events are also appended to the agent's log file,
which is the durable record.

```
jit agent history [flags]
```

### Options

```
      --format string   output format: "text" (default) or "json" (default "text")
```

### SEE ALSO

* [jit agent](jit_agent.md)	 - Run a background helper so you only unlock once, not once per command

