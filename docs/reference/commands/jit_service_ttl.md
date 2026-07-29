## jit service ttl

Show or change how long a session stays unlocked before it auto-locks

### Synopsis

With no argument, prints the session TTL the background service is currently
configured with. With a duration (e.g. 30s, 10m, 1h), changes it.

The TTL is how long an unlocked session stays cached after your last Touch
ID prompt before it locks itself, so the next use prompts again (default
5m). It is baked into the service's login item, so a change persists across
logins and reboots, not just this one.

It is an INACTIVITY timeout, so use pushes it back — and a session also ends
8 hours after the unlock that started it, however busy it has been. Values
above that ceiling are refused rather than accepted and quietly ignored: an
idle timeout longer than the maximum session age could never be reached.

Changing it restarts the background service, so the current session is
dropped and the next vault use prompts Touch ID once. Your vault and the
session history are untouched.

```
jit service ttl [duration]
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit service](jit_service.md)	 - Manage jit's background service (the daemon that holds your session and serves mounts)

