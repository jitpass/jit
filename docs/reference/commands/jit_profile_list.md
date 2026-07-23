## jit profile list

Deprecated: use `jit status --secrets`

### Synopsis

Lists the profile manifests visible from the current directory.

Deprecated: this only ever shows the manifests in this folder, never the
secrets those manifests don't touch — so a vault full of secrets can look
empty here. `jit status --secrets` reconciles the two: which stored secrets
are wired to a profile, which are managed elsewhere, and which are orphaned.

```
jit profile list
```

### SEE ALSO

* [jit profile](jit_profile.md)	 - Inspect profile manifests (names and vault paths only, never secret values)

