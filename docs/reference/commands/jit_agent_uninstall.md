## jit agent uninstall

Stop jit agent and remove it from login startup

### Synopsis

Stops the background helper and removes it from login startup, it will
no longer start automatically. Any files it was live-mounting stop being
served (they don't disappear; they just go quiet until you run
`jit agent install` again). Doesn't touch the vault or any secrets
already stored, only the background helper itself.

```
jit agent uninstall
```

### SEE ALSO

* [jit agent](jit_agent.md)	 - Run a background helper so you only unlock once, not once per command

