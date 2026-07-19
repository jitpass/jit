## jit wrap add

Wrap a tool by hand: a shim on PATH that injects a profile or grants a global mount

### Synopsis

jit wrap add installs a shim so a tool works by its native name. Two forms:
--env wraps a tool that reads a token from an ENV VAR (gh, stripe): the shim
injects a wrap-<tool> profile. --grant wraps a tool that reads a machine-wide
credential FILE (gcloud reads the gcp ADC): the shim runs `jit run --with
<name>` so the tool gets the real file, gated by a disclosed challenge.

```
jit wrap add <tool> --env VAR=<vault-path> [--env ...] | --grant <name> [flags]
```

### Examples

```
  jit vault set wrap-gh/GH_TOKEN
  jit wrap add gh --env GH_TOKEN=wrap-gh/GH_TOKEN
  jit wrap add gcloud --grant gcp
```

### Options

```
      --env stringArray   environment variable to inject, as VAR=<vault-path> (repeatable)
      --grant string      grant a global file-delivered mount by name (gcp, sops, npm) instead of injecting an env var - for tools that read a credential file
```

### SEE ALSO

* [jit wrap](jit_wrap.md)	 - Wrap CLI tools so their tokens are injected just-in-time

