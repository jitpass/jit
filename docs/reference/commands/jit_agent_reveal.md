## jit agent reveal

Temporarily show real secret values in a live-mounted file

### Synopsis

A live-mounted file (the kind jit migrate creates for .env/npmrc) shows
fake-looking values by default and only its real ones while "revealed".
Every unlock/refresh already reveals every mount for a short default
window automatically; this command is for when that's not enough (a
dev server that reads .env well after the window closed).
Requires the agent to be unlocked, prompting Touch ID/passcode if it isn't.

Meant to be embedded in a pre-run hook (jit migrate wires this up
automatically for direnv/npm projects) as well as run by hand.

```
jit agent reveal <mount-path> [flags]
```

### Options

```
      --for duration   how long to serve real content (clamped to 10m) (default 5m0s)
  -q, --quiet          suppress the success message — for embedding in a pre-run hook
```

### SEE ALSO

* [jit agent](jit_agent.md)	 - Run a background helper so you only unlock once, not once per command

