## jit grant

Pre-approve a running process to use profiles unattended

### Synopsis

Create a process grant: with one Touch ID now, allow a process that is
already running (and everything it launches) to use the named profiles'
secrets without further prompts, until the grant expires — including while
the screen is locked or you are away.

The grant is anchored to the live process you name, not to its name: a new
process called the same thing tomorrow inherits nothing. It covers exactly
the secrets the named profiles resolve to at creation time, ends at its
deadline (or when the process exits, or on 'jit grant revoke'), and every
serve under it is recorded in 'jit audit'.

Grants live in the service's memory: they survive screen lock by design,
and do not survive a service restart or reboot.

```
jit grant --process NAME --profile NAME --for DURATION [flags]
```

### Examples

```
  # let the running claude session use the jamf profile for 8 hours
  jit grant --process claude --profile jamf --for 8h

  # several profiles in one grant, anchored by pid when the name is ambiguous
  jit grant --pid 4211 --profile jamf --profile aws-ci --for 1d

  # see, shorten, or end what is open
  jit grant list
  jit grant revoke g-7f3a
  jit grant extend g-7f3a --for 24h
```

### Options

```
      --for string            how long the grant lasts (45m, 8h, 3d - max 7d)
      --pid int32             running process the grant anchors to, by pid (when --process is ambiguous)
      --process string        running program the grant anchors to, by name (tab-completes from recent callers)
      --profile stringArray   profile whose secrets the grant covers (repeatable)
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime
* [jit grant extend](jit_grant_extend.md)	 - Give an existing grant more time (re-prompts Touch ID)
* [jit grant list](jit_grant_list.md)	 - Show the active process grants
* [jit grant revoke](jit_grant_revoke.md)	 - End a process grant now

