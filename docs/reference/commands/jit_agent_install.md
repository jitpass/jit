## jit agent install

Start jit agent automatically at every login (survives reboots)

### Synopsis

You usually don't need to run this: jit sets the agent up automatically
the first time a command needs it. Run it yourself to do that eagerly, or
to choose the session --ttl up front.

Sets up jit agent to start automatically every time you log in, and to
restart itself if it crashes, until you run `jit agent uninstall`.
Under the hood this writes and loads a launchd LaunchAgent plist that
runs `jit agent run`.

--ttl controls how long a session stays unlocked after your last Touch ID
prompt (default 5m, same meaning as `jit agent run --ttl`), baked into
the installed service so it applies from every future login, not just
this one.

Safe to run again to change --ttl later: an already-installed instance is
unloaded first, so the new value takes effect immediately rather than
only on the next login.

```
jit agent install [flags]
```

### Options

```
      --ttl duration   how long an unlocked session stays cached before auto-locking, baked into the installed plist (default 5m0s)
  -y, --yes            skip the confirmation prompt and install immediately
```

### SEE ALSO

* [jit agent](jit_agent.md)	 - Run a background helper so you only unlock once, not once per command

