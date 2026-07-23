## jit lock

Lock jit's session immediately, without waiting for the TTL

### Synopsis

Locks the shared session jit's background service holds, right now, instead
of waiting out the remaining --ttl. The next vault use prompts Touch ID
again, and live-mounted files serve placeholder values until then.

```
jit lock
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

