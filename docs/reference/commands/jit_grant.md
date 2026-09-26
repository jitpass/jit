## jit grant

Pre-approve a program to use profiles unattended

### Synopsis

Create a process grant: with one Touch ID now, allow a program (and
everything it launches) to use the named profiles' secrets without further
prompts - including while the screen is locked or you are away.

You choose how it ends, and the two shapes differ in more than duration:

  --for DURATION    until a deadline, at most 7d. The grant lives in the
                    service's memory, so it also ends if the service stops
                    or the terminal it is anchored to quits.
  --until-revoked   until you run 'jit grant revoke'. The grant holds a key
                    of its own, so it survives screen lock, a service
                    restart and a reboot.

--process NAME is scoped to the terminal you type it in: every NAME under
this terminal - running now or started later, in any tab - is covered. The
anchor is the terminal app itself, verified through kernel ancestry, so a
same-named process elsewhere on the machine inherits nothing. --pid grants
one exact running process instead and ends when it exits; it always takes
--for, because one process cannot outlive a reboot.

A grant covers exactly the secrets the named profiles resolve to at
creation time, and every serve under it is recorded in 'jit audit'. If one
of those secrets is rotated it stops being served and 'jit grant list'
says so; the rest keep working.

```
jit grant --process NAME --profile NAME (--for DURATION | --until-revoked) [flags]
```

### Examples

```
  # let claude use the myapp profile for 8 hours - current sessions and
  # any started from this terminal within the window
  jit grant --process claude --profile myapp --for 8h

  # no deadline: until you revoke it, across restarts and reboots
  jit grant --process claude --profile mcp-github --until-revoked

  # several profiles, for one exact running process only
  jit grant --pid 4211 --profile myapp --profile aws-ci --for 1d

  # see, shorten, or end what is open
  jit grant list
  jit grant revoke g-7f3a
  jit grant extend g-7f3a --for 24h
```

### Options

```
      --for string            how long the grant lasts (45m, 8h, 3d - max 7d)
      --pid int32             one exact running process to grant instead (ends when it exits)
      --process string        program to cover, by name: every one under this terminal, running or started later
      --profile stringArray   profile whose secrets the grant covers (repeatable)
      --until-revoked         no deadline: the grant holds its own key, survives restarts and reboots, and ends on jit grant revoke (--process only)
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

