## jit agent

Run a background helper so you only unlock once, not once per command

### Synopsis

jit agent is a small background helper that keeps one unlocked session
other jit commands share, instead of each one prompting Touch ID
separately, and that serves any live-mounted .env files jit migrate has
created.

`jit agent install` sets it up to start automatically every time you log
in (and restart itself if it crashes). The helper process itself needs no
Touch ID just to keep running, only your unlocked session inside it locks
after --ttl of inactivity (default 15m), prompting again on next use.

A live-mounted file shows fake-looking values until revealed, and real values
only during a short window, opened automatically right after unlock/
refresh, or explicitly via `jit agent reveal`.

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime
* [jit agent history](jit_agent_history.md)	 - List every unlock, lock, denial, and use this agent has seen, and what caused them
* [jit agent install](jit_agent_install.md)	 - Start jit agent automatically at every login (survives reboots)
* [jit agent lock](jit_agent_lock.md)	 - Lock the running agent's session immediately, without waiting for the TTL
* [jit agent log](jit_agent_log.md)	 - Show the agent's own log (session events, mount reads, serve errors)
* [jit agent restart](jit_agent_restart.md)	 - Restart the agent process (picks up a newly built or updated jit binary)
* [jit agent reveal](jit_agent_reveal.md)	 - Temporarily show real secret values in a live-mounted file
* [jit agent run](jit_agent_run.md)	 - Run the agent in the foreground (normally started by launchd, not by hand)
* [jit agent status](jit_agent_status.md)	 - Show whether the agent is running, and whether its session is unlocked
* [jit agent uninstall](jit_agent_uninstall.md)	 - Stop jit agent and remove it from login startup
* [jit agent unlock](jit_agent_unlock.md)	 - Unlock the running agent's session now (prompts Touch ID if needed)

