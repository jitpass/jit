## jit grant

Pre-approve a program to use profiles unattended

### Synopsis

Create a process grant: with one Touch ID now, allow a program (and
everything it launches) to use the named profiles' secrets without further
prompts, until the grant expires - including while the screen is locked or
you are away.

--process NAME is scoped to the terminal you type it in: every NAME under
this terminal - running now or started later, in any tab - is covered
until the deadline. The anchor is the terminal app itself, verified
through kernel ancestry, so a same-named process elsewhere on the machine
inherits nothing, and the grant ends early if the terminal app quits.
--pid grants one exact running process instead, and ends when it exits.

A grant covers exactly the secrets the named profiles resolve to at
creation time, ends at its deadline (or on 'jit grant revoke'), and every
serve under it is recorded in 'jit audit'.

Grants live in the service's memory: they survive screen lock by design,
and do not survive a service restart or reboot.

```
jit grant --process NAME --profile NAME --for DURATION [flags]
```

### Examples

```
  # let claude use the jamf profile for 8 hours - current sessions and
  # any started from this terminal within the window
  jit grant --process claude --profile jamf --for 8h

  # several profiles, for one exact running process only
  jit grant --pid 4211 --profile jamf --profile aws-ci --for 1d

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

