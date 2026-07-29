## jit unlock

Unlock jit's session now (prompts Touch ID if needed)

### Synopsis

Unlocks the shared session jit's background service holds, prompting Touch ID
or your device passcode if it isn't already unlocked. Pre-warms it so a
following jit run / vault get / export doesn't stop to prompt. It locks
itself again after the session --ttl of inactivity, at the 8-hour maximum
session age whichever comes first, or on `jit lock` sooner.

An unlock that actually prompts you also clears any consent pauses: a
refused credential prompt holds that caller off for a few seconds, and you
standing at the keyboard is exactly the "now" that refusal withheld. An
unlock while the session is already open prompts nobody, so it clears
nothing — otherwise any process could reset the pause by asking for one.

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

