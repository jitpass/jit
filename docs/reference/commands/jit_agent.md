## jit agent

Run a background helper so you only unlock once, not once per command

### Synopsis

jit agent is a small background helper that keeps one unlocked session
other jit commands share, instead of each one prompting Touch ID
separately, and that serves any live-mounted .env files jit migrate has
created.

You usually don't need to set this up by hand: jit installs the agent
automatically the first time a command needs it (a `jit run` that serves a
mount, a `jit migrate`, or `jit agent unlock`). `jit agent install` just
does that eagerly and lets you pick the session --ttl up front. Either way
it starts automatically at every login (and restarts itself if it crashes).
The helper process itself needs no Touch ID just to keep running, only your
unlocked session inside it locks after --ttl of inactivity (default 5m),
prompting again on next use.

A live-mounted file shows fake-looking values by default. Real values flow
only to a `jit run` grant's own process tree: `jit run --live` for a project
mount, `jit run --with` for a global credential. Unlocking the vault never
makes a mount serve real values on its own.

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime
* [jit agent history](jit_agent_history.md)	 - List every unlock, lock, denial, and use this agent has seen, and what caused them
* [jit agent install](jit_agent_install.md)	 - Start jit agent automatically at every login (survives reboots)
* [jit agent lock](jit_agent_lock.md)	 - Lock the running agent's session immediately, without waiting for the TTL
* [jit agent log](jit_agent_log.md)	 - Show the agent's own log (session events, mount reads, serve errors)
* [jit agent restart](jit_agent_restart.md)	 - Restart the agent process (picks up a newly built or updated jit binary)
* [jit agent run](jit_agent_run.md)	 - Run the agent in the foreground (normally started by launchd, not by hand)
* [jit agent status](jit_agent_status.md)	 - Show whether the agent is running, and whether its session is unlocked
* [jit agent uninstall](jit_agent_uninstall.md)	 - Stop jit agent and remove it from login startup
* [jit agent unlock](jit_agent_unlock.md)	 - Unlock the running agent's session now (prompts Touch ID if needed)

