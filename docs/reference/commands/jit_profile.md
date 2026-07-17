## jit profile

Inspect profile manifests (names and vault paths only, never secret values)

### Synopsis

A profile maps environment variable names to vault secret paths.
jit profile lists and shows these manifests, both project-local ones
under .jit/profiles/ and the home-rooted global ones jit migrate creates
for shell-config/MCP/AWS/kubeconfig/npmrc secrets, without ever decrypting
or printing a secret value. Use jit doctor to also verify a profile's
referenced secrets actually exist in the vault.

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime
* [jit profile list](jit_profile_list.md)	 - List every profile manifest visible from the current directory
* [jit profile show](jit_profile_show.md)	 - Show a profile's variable-to-vault-path mapping

