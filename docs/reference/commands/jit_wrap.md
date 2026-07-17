## jit wrap

Wrap CLI tools so their tokens are injected just-in-time

### Synopsis

jit wrap puts a shim first on PATH for each wrapped tool: you keep typing
`gh` exactly as before, and the token materializes only inside that one
process (via `jit run --profile wrap-<tool>`), never in a plaintext config
file. Works in scripts, Makefiles, and tools spawning tools, anywhere the
binary is invoked, not just interactive shells.

Store the secret first (`jit vault set`), then describe the tool:
`jit wrap add <tool> --env VAR=<vault-path>`. See docs/wrap/ for the
catalog of known tools with automatic discovery.

```
jit wrap
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime
* [jit wrap add](jit_wrap_add.md)	 - Wrap a tool by hand: shim on PATH + a wrap-<tool> profile
* [jit wrap doctor](jit_wrap_doctor.md)	 - Verify every wrapped tool's shim, PATH entry, and profile
* [jit wrap list](jit_wrap_list.md)	 - Show wrapped tools and their shim health
* [jit wrap undo](jit_wrap_undo.md)	 - Unwrap a tool: remove its shim and wrap profile

