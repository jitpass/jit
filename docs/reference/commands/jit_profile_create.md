## jit profile create

Write a profile manifest

### Synopsis

Writes a profile manifest: the file mapping environment variable
names to vault paths that `jit run --profile <name>` reads.

With no VAR=<vault path> pairs, the variables are taken from the
vault group of the same name — every secret in it becomes a variable
named as the secret is named. That is the shape `jit migrate` writes,
so a profile lost while its secrets survived comes back with just its
name. --from takes them from a differently named group.

Writes to ./.jit/profiles by default, so the manifest sits beside the
project it serves and can be committed with it; --global writes to
~/.jit/profiles, where MCP and shell profiles live. An existing
manifest is never overwritten without --force.

Only names are read from the vault and only names are written, so no
value is decrypted and no Touch ID is needed.

```
jit profile create <name> [VAR=<vault path>]... [flags]
```

### Examples

```
  jit profile create mcp-jamf
  jit profile create mcp-jamf --global
  jit profile create mcp-jamf --from jamf
  jit profile create deploy AWS_SECRET=aws-prod/SECRET DB_URL=rds/URL
```

### Options

```
      --dry-run       print the manifest; write nothing
      --force         replace an existing manifest
      --from string   take the variables from this vault group instead of <name>
      --global        write to ~/.jit/profiles instead of ./.jit/profiles
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit profile](jit_profile.md)	 - Write, edit, and delete profile manifests

