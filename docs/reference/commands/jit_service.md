## jit service

Manage jit's background service (the daemon that holds your session and serves mounts)

### Synopsis

jit runs a small background service: a login-time daemon that keeps one
unlocked session other jit commands share, instead of each one prompting
Touch ID separately, and that serves any live-mounted .env files jit migrate
has created.

It is a solid part of jit, not an optional add-on: it sets itself up the
first time a command needs it (a `jit run` that serves a mount, a `jit
migrate`, or `jit unlock`), starts at every login, and restarts itself if it
crashes. There is no install step. These subcommands are for the rare times
you want to manage it by hand: `jit service ttl` shows or changes how long a
session stays unlocked, `jit service status` reports its health, `jit service
restart` restarts it (and brings it back if it ever stopped), and `jit
service log` shows its own output. It goes away when you remove jit itself.
The service process itself needs no Touch ID just to keep running, only your
unlocked session inside it locks after the TTL of inactivity (default 5m),
prompting again on next use.

To control the session itself, use the top-level `jit unlock` and `jit lock`.
To see what the service has done (unlocks, denials, mount reads), use
`jit audit`.

A live-mounted file shows fake-looking values by default. Real values flow
only to a `jit run` grant's own process tree: `jit run --live` for a project
mount, `jit run --with` for a global credential. Unlocking the vault never
makes a mount serve real values on its own.

```
jit service
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime
* [jit service consent](jit_service_consent.md)	 - Show or set per-process credential consent
* [jit service log](jit_service_log.md)	 - Show the service's raw operational output (startup, mount notes, serve errors)
* [jit service restart](jit_service_restart.md)	 - Restart the background service (picks up a new binary, or brings a stopped one back)
* [jit service run](jit_service_run.md)	 - Run the service in the foreground (normally started by launchd, not by hand)
* [jit service status](jit_service_status.md)	 - Show whether the service is running, and whether its session is unlocked
* [jit service ttl](jit_service_ttl.md)	 - Show or change how long a session stays unlocked before it auto-locks

