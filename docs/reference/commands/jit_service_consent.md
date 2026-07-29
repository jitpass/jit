## jit service consent

Show or set per-process credential consent

### Synopsis

Per-process credential consent (on by default): the background service
prompts a fresh Touch ID the first time each tool reaches for a credential
(AWS, git, docker, kube, gcloud/sops/npm/netrc keys), naming who is asking,
and remembers your answer for the session. It closes the window where any
process running as you can use a migrated credential silently while your
vault is unlocked.

Saying no is meant to be cheap. A refused prompt is not remembered as a
lasting "no" — it can't be, since a decline and a keychain failure look the
same from here — so instead it pauses that caller for a few seconds, then
longer if it keeps asking, and the prompt tells you how many times it has
already been refused. Nothing is locked out: the next genuine attempt still
asks, and an approval (or a fresh `jit unlock`) clears the pause.

With no argument, prints whether it's on. `on`/`off` set it and restart the
service; turning it OFF requires a fresh Touch ID/passcode, since disabling
the guard reopens the window it closes. Use `jit run --trust -- <cmd>` to
pre-authorize a whole run's tree so it isn't prompted.

```
jit service consent [on|off]
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit service](jit_service.md)	 - Manage jit's background service (the daemon that holds your session and serves mounts)

