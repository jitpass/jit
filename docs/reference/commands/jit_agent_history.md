## jit agent history

List every unlock, lock, denial, and use this agent has seen, and what caused them

### Synopsis

Prints the agent's session history, most recent first: every Touch ID prompt
that succeeded (with the command that triggered it and what launched that
command), every prompt that was DECLINED (same provenance, plus why it
failed), every lock (with its cause — an idle timeout, the screen locking,
or an explicit `jit agent lock`), every use of the already-unlocked session
(what flowed through it, collapsed per caller, with the secret names the
caller reported), and every agent start.

This is the answer to "why does it keep asking me?" — a question the agent
previously had no way to answer, since only locks were ever recorded and the
unlocks that did the prompting left no trace at all.

Survives restarts: events are also written to agent-history.jsonl alongside
the vault, and each new agent process picks the newest back up — so asking
about yesterday's prompts works even though logging in this morning restarted
the agent. Agent starts appear in the list, marking where one process's
events end and the previous one's begin.

```
jit agent history [flags]
```

### Options

```
      --format string   output format: "text" (default) or "json" (default "text")
```

### SEE ALSO

* [jit agent](jit_agent.md)	 - Run a background helper so you only unlock once, not once per command

