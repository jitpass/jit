## jit wrap add

Wrap a tool by hand: shim on PATH + a wrap-<tool> profile

```
jit wrap add <tool> --env VAR=<vault-path> [--env ...] [flags]
```

### Examples

```
  jit vault set wrap-gh/GH_TOKEN
  jit wrap add gh --env GH_TOKEN=wrap-gh/GH_TOKEN
```

### Options

```
      --env stringArray   environment variable to inject, as VAR=<vault-path> (repeatable)
```

### SEE ALSO

* [jit wrap](jit_wrap.md)	 - Wrap CLI tools so their tokens are injected just-in-time

