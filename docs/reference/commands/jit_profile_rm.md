## jit profile rm

Delete a global profile and the secrets nothing else uses

### Synopsis

Deletes a global profile: its manifest, its record of the configs
that use it, and each of its secrets no other profile or pointer file
uses. Secrets another profile uses are kept.

A profile a tool still uses is refused, and nothing is deleted: an MCP
server entry (any wrapper layer), an AWS or kubeconfig entry, a wrapped
tool, a mount, a shell rc export or a credential helper, found anywhere
under your home folder. Remove that first. If jit can't read one of
those files, it can't tell, and refuses the same way. Scripts and
aliases can't be seen, so "no known tool" is never proof the profile
is unused.

A project profile goes with its project: `jit migrate remove <project>`.

Beyond the [y/N] confirmation, deleting secrets needs a fresh Touch ID;
-y/--yes skips only the confirmation. --dry-run shows the plan and
stops. With --format json it prints profile, scope, launchers,
delete_secrets, keep_secrets, missing_secrets, coverage_complete,
refused and error.

```
jit profile rm <profile> [flags]
```

### Examples

```
  jit profile rm k8s-docker-desktop
  jit profile rm --dry-run --format json token
```

### Options

```
      --dry-run         show what would be deleted and what uses it; change nothing
      --format string   dry-run output format: "text" (default) or "json" (default "text")
  -y, --yes             skip the confirmation prompt (never Touch ID)
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit profile](jit_profile.md)	 - Write, edit, and delete profile manifests

