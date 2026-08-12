## jit status

One-shot overview of vault, service, secret, and mount health

### Synopsis

Rolls up what previously took several separate commands to piece together, is the vault initialized, is the service running and unlocked, how do this project's stored secrets line up against its profiles, are mounts being served, into one read-only report. Never decrypts a secret value or triggers a Touch ID/passcode prompt, matching jit doctor's own safe-to-run-often shape; each section points at the dedicated command for full detail rather than duplicating it.

The Secrets section reconciles the vault against the profiles jit can see: every stored secret is wired here (a project-local profile uses it), managed elsewhere (referenced only by a global profile or a mount), or unreferenced (a candidate orphan). Add --secrets to expand it into the full per-group listing.

An unreferenced group holding the same key names as a group still in use is called out as such: usually a second migration renamed the group and left the original copy behind, and those leftovers are usually the bulk of what jit vault orphans would prune. Key names are compared, never values, since status never decrypts.

--format json prints a machine-readable snapshot instead of the default text report, in the same shape jit service status/vault list/doctor's own --format json use for their overlapping sections.

```
jit status [flags]
```

### Examples

```
  jit status
  jit status --secrets     # per-group vault/profile reconciliation
  jit status --format json
```

### Options

```
      --format string   output format: "text" (default) or "json" (default "text")
      --secrets         expand the Secrets section into a full per-group reconciliation
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

