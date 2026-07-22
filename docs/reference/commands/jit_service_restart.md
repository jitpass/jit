## jit service restart

Restart the background service (picks up a new binary, or brings a stopped one back)

### Synopsis

Restarts jit's background service. Two uses: the immediate fix when
`jit service status` warns that the running service predates the jit binary
on disk (the service also retires itself onto the new binary automatically,
but only once its session is locked and no prompt is pending; restart is for
wanting it now), and the way to bring the service back if it stopped.

If the login item is missing entirely (it was never started, or was
removed), this recreates it — jit keeps the service installed as a matter of
course, so there is no separate install step.

The in-memory session is lost, so the next vault use prompts Touch ID
again, and live-mounted files serve placeholder values until then.
Session history survives, it's durable.

```
jit service restart
```

### SEE ALSO

* [jit service](jit_service.md)	 - Manage jit's background service (the daemon that holds your session and serves mounts)

