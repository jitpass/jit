## jit profile

Inspect profile manifests (names and vault paths only, never secret values)

### Synopsis

A profile maps environment variable names to vault secret paths.
jit profile show prints one profile's mapping, both project-local ones
under .jit/profiles/ and the home-rooted global ones jit migrate creates
for shell-config/MCP/AWS/kubeconfig/npmrc secrets, without ever decrypting
or printing a secret value.

For the whole picture — which stored secrets are wired to a profile, which
are managed elsewhere, and which are orphaned — use jit status --secrets
(the successor to the deprecated jit profile list). Use jit doctor to also
verify a profile's referenced secrets actually exist in the vault.

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime
* [jit profile list](jit_profile_list.md)	 - Deprecated: use `jit status --secrets`
* [jit profile show](jit_profile_show.md)	 - Show a profile's variable-to-vault-path mapping

