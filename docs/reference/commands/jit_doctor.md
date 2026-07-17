## jit doctor

Verify every secret a profile references actually exists in the vault

### Synopsis

jit doctor checks that every secret path a profile manifest references
actually exists in the vault, failing fast with a named missing secret
instead of letting an app crash later on an empty environment variable.
Only checks existence, never decrypts a value, so it never needs local
authentication.

By default checks every profile visible from the current directory: both
project-local ones under .jit/profiles/ and the home-rooted global ones
jit migrate writes for shell-config/MCP/AWS/kubeconfig/npmrc secrets,
the same set `jit profile list` shows. Use --profile to check just one.
--format json prints a machine-readable snapshot instead of the default
text report, still exits non-zero on any problem either way.

```
jit doctor [flags]
```

### Options

```
      --format string    output format: "text" (default) or "json" (default "text")
      --profile string   check only this profile instead of every profile under .jit/profiles/
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

