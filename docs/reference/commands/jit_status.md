## jit status

One-shot overview of vault, agent, profile, and mount health

### Synopsis

Rolls up what previously took several separate commands to piece together, is the vault initialized, is the agent running and unlocked, do this project's profiles resolve, are mounts being served, into one read-only report. Never decrypts a secret value or triggers a Touch ID/passcode prompt, matching jit doctor and jit profile's own safe-to-run-often shape; each section points at the dedicated command for full detail rather than duplicating it.

--format json prints a machine-readable snapshot instead of the default text report, in the same shape jit agent status/vault list/doctor's own --format json use for their overlapping sections.

```
jit status [flags]
```

### Options

```
      --format string   output format: "text" (default) or "json" (default "text")
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

