## jit migrate caches

Remove copies of your vaulted secrets that AI agents cached (whole-vault sweep)

### Synopsis

jit migrate caches searches every AI coding agent's local cache — Claude
Code's file-history, paste-cache and transcripts, and the equivalents for
Cursor, Cline, OpenCode, Codex and others — for verbatim copies of any
credential currently in your vault, and redacts each copy in place,
replacing it with a <jit:redacted:VAR> marker naming the vault entry.

`jit migrate` already does this automatically for the secrets each run
moves. This command is the whole-vault version, and it reaches what that
per-run sweep cannot: a secret you migrated before this feature existed,
a copy left in a Claude session that was live during an earlier migrate
(run this once the session has ended), and tokens captured by jit wrap.

It decrypts every secret in the vault, so it asks for Touch ID up front —
that prompt is the consent for reading the whole vault at once. A file an
agent is writing at that moment is left alone and reported; a binary
store (a SQLite session db) is reported, never rewritten, because a
length-changing edit would corrupt it. Every file jit does rewrite is
backed up encrypted first — `jit migrate undo <path>` restores it.

```
jit migrate caches
```

### Examples

```
  jit migrate caches            # clean copies of every vaulted secret
  jit migrate caches --dry-run  # show what would be cleaned, change nothing
```

### Options inherited from parent commands

```
      --dry-run        preview the plan without changing anything
      --only strings   scope a run to just these comma-separated categories: env,tfvars,k8s-secret,shell,history,mcp,aws,kube,terraform,docker,git,gcp,sops,npmrc,netrc,pypirc,loose,cache (default: all)
      --quiet          suppress the progress spinner/status trail (results still print)
  -y, --yes            skip the confirmation prompt and proceed immediately
```

### SEE ALSO

* [jit migrate](jit_migrate.md)	 - Guided fix path for findings jit scan reports (name the file(s) to convert)

