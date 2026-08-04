## jit guard

Prevention hooks that keep credentials from being recorded in the first place

### Synopsis

jit guard installs prevention hooks: where jit scan finds credentials that
were already recorded and jit migrate cleans them up, a guard stops the
recording from happening at all.

The first guard is the shell history guard (`jit guard history`).

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime
* [jit guard history](jit_guard_history.md)	 - Keep typed credentials out of your shell history file (zsh)

