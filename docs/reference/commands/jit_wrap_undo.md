## jit wrap undo

Unwrap a tool: remove its shim and wrap profile

### Synopsis

jit wrap undo removes a tool's shim and its wrap profile. For a CLI whose
login jit sealed (gcloud and its family, az), it first writes the login
back to the tool's own folder in plaintext (after a fresh Touch ID) and
unwraps every tool that reads it; the vault copy is kept.

```
jit wrap undo <tool> [flags]
```

### Options

```
      --dry-run   preview what unwrapping would do without changing anything
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit wrap](jit_wrap.md)	 - Wrap CLI tools so their tokens are injected just-in-time

