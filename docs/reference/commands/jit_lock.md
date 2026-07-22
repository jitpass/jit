## jit lock

Lock jit's session immediately, without waiting for the TTL

### Synopsis

Locks the shared session jit's background service holds, right now, instead
of waiting out the remaining --ttl. The next vault use prompts Touch ID
again, and live-mounted files serve placeholder values until then.

```
jit lock
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

