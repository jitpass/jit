## jit agent restart

Restart the agent process (picks up a newly built or updated jit binary)

### Synopsis

Kills and restarts the launchd-managed agent process — the immediate fix
when `jit agent status` warns that the running agent predates the jit
binary on disk. (The agent also retires itself onto the new binary
automatically, but only once its session is locked and no prompt is
pending; restart is for wanting it now.)

The in-memory session is lost, so the next vault use prompts Touch ID
again, and live-mounted files serve placeholder values until then.
Session history survives — it's durable. Requires `jit agent install`.

```
jit agent restart
```

### SEE ALSO

* [jit agent](jit_agent.md)	 - Run a background helper so you only unlock once, not once per command

