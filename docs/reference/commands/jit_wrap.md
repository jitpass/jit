## jit wrap

Wrap CLI tools so their tokens are injected just-in-time

### Synopsis

jit wrap puts a shim first on PATH for each wrapped tool: you keep typing
`gh` exactly as before, and the token materializes only inside that one
process (via `jit run --profile wrap-<tool>`), never in a plaintext config
file. Works in scripts, Makefiles, and tools spawning tools, anywhere the
binary is invoked, not just interactive shells.

A catalog tool is wrapped by name: `jit wrap gh`. For a CLI that keeps
its own login (`jit wrap gcloud`, `jit wrap az`) the wrap seals that
login in the vault instead, and each run unseals it for that one run.
Any other tool: store the secret first (`jit vault set`), then
`jit wrap add <tool> --env VAR=<vault-path>`. See docs/wrap/ for the
catalog of known tools with automatic discovery.

```
jit wrap [<tool>] [flags]
```

### Options

```
      --dry-run         preview what wrapping would do without changing anything
      --format string   output format: "text" (default), or "json": what the wrap did, as one document; a native tool needs --yes (default "text")
  -y, --yes             for a native tool (aws, docker, git, terraform): skip the migration's confirmation prompt
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime
* [jit wrap add](jit_wrap_add.md)	 - Wrap a tool by hand: a shim on PATH that injects a profile or grants a global mount
* [jit wrap list](jit_wrap_list.md)	 - Show wrapped tools and their shim health
* [jit wrap undo](jit_wrap_undo.md)	 - Unwrap a tool: remove its shim and wrap profile

