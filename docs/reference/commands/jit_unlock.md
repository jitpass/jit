## jit unlock

Unlock jit's session now (prompts Touch ID if needed)

### Synopsis

Unlocks the shared session jit's background service holds, prompting Touch ID
or your device passcode if it isn't already unlocked. Pre-warms it so a
following jit run / vault get / export doesn't stop to prompt, and locks
itself again after the session --ttl of inactivity (or `jit lock` sooner).

If the background service isn't set up yet, this sets it up first: `unlock`
is the "get me a session" intent, so there's nothing extra to run by hand.

```
jit unlock
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

