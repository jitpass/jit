## jit profile

Write, edit, and delete profile manifests

### Synopsis

A profile maps variables to vault secrets; `jit run --profile` resolves
it. A profile made from an MCP config records that config, which is
what `jit migrate remove` goes by.

`jit profile create` writes a manifest: every secret in a vault group of
the same name, or the variable=path pairs you name. It is how a manifest
lost with its project comes back beside a vault that survived.
`jit profile drop` removes variables from a manifest, leaving the
secrets they named in the vault.
`jit profile attach` records a config on the profiles its tools use but
that don't record it (the recorded config was deleted, or the config
was copied).
`jit profile rm` deletes a global profile no known tool uses, with the
secrets nothing else uses.

```
jit profile
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime
* [jit profile attach](jit_profile_attach.md)	 - Record an MCP config on the profiles its tools use
* [jit profile create](jit_profile_create.md)	 - Write a profile manifest
* [jit profile drop](jit_profile_drop.md)	 - Remove variables from a profile manifest
* [jit profile rm](jit_profile_rm.md)	 - Delete a global profile and the secrets nothing else uses

