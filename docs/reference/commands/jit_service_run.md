## jit service run

Run the service in the foreground (normally started by launchd, not by hand)

```
jit service run [flags]
```

### Options

```
      --ttl duration   how long an unlocked session stays cached before auto-locking (default 5m0s)
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit service](jit_service.md)	 - Manage jit's background service (the daemon that holds your session and serves mounts)

