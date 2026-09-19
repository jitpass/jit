## jit profile

Manage which configs own a profile, and delete one

### Synopsis

A profile maps variables to vault secrets; `jit run --profile` resolves
it. A profile made from an MCP config records that config as its owner,
which is what `jit migrate remove` goes by.

`jit profile adopt` makes a config the owner of profiles it launches but
doesn't own (its owner was deleted, or the config was copied).
`jit profile rm` deletes a global profile nothing known launches, with
the secrets nothing else uses.

```
jit profile
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime
* [jit profile adopt](jit_profile_adopt.md)	 - Make an MCP config the owner of the profiles it launches
* [jit profile rm](jit_profile_rm.md)	 - Delete a global profile and the secrets nothing else uses

