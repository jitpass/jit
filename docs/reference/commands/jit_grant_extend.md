## jit grant extend

Give an existing grant more time (re-prompts Touch ID)

### Synopsis

Move a grant's deadline to now plus the new duration. More time is a new
decision, so this puts the same disclosed prompt in front of you that
creating the grant did. Shortening needs no command of its own: revoke and
re-create, and neither step re-asks for what you already have.

```
jit grant extend ID --for DURATION [flags]
```

### Options

```
      --for string   new lifetime from now (45m, 8h, 3d - max 7d)
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit grant](jit_grant.md)	 - Pre-approve a running process to use profiles unattended

