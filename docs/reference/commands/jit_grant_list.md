## jit grant list

Show the active process grants

### Synopsis

List every live process grant: who holds it, which profiles it covers,
how it ends - at a deadline, or only when you revoke it - and how many
serves have ridden it. A covered secret that has been rotated is flagged
here, because a rotated secret stops being served. Reading this never
prompts.

```
jit grant list [flags]
```

### Options

```
      --format string   output format: text or json (default "text")
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit grant](jit_grant.md)	 - Pre-approve a program to use profiles unattended

