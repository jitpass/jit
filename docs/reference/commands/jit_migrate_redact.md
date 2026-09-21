## jit migrate redact

Replace tokens AI agents cached — found by their format — with a marker

### Synopsis

jit migrate redact searches every AI coding agent's local cache — Claude
Code's transcripts, file-history and paste-cache, and the equivalents for
Cursor, Codex, Gemini and others — for credentials it recognises by their
format (the same vendor formats jit scan reports), and replaces each one in
place with a <jit:redacted:VENDOR> marker, the rest of the line untouched.

It is the fix for a token an agent cached that was never in your vault: a
key pasted into a prompt, a snapshot of a file you have since rotated.
`jit migrate caches` is the other half, for copies of vaulted secrets.

Only agent caches are rewritten, never a file of your own. There is no
backup and no Touch ID: the change is one-way, the marker says what was
there. A file an agent is writing at that moment is left alone and
reported; a binary store is reported, never rewritten. Name files to
limit the sweep to them; --line limits it to tokens on those lines.

```
jit migrate redact [file...] [flags]
```

### Examples

```
  jit migrate redact                        # every agent cache
  jit migrate redact --dry-run              # show what would change, change nothing
  jit migrate redact ~/.claude/projects/x/s.jsonl --line 1046
```

### Options

```
      --format string   output format: "text" (default), or "json": one document naming what was redacted and what was left; needs --yes (default "text")
      --line ints       only tokens on these 1-based lines of the named files (repeatable)
```

### Options inherited from parent commands

```
      --dry-run        preview the plan without changing anything
      --only strings   scope a run to just these comma-separated categories: env,tfvars,k8s-secret,shell,history,mcp,aws,kube,terraform,docker,git,gcp,sops,npmrc,netrc,pypirc,cargo,streamlit,loose,cache (default: all)
      --quiet          suppress the progress spinner/status trail (results still print)
  -y, --yes            skip the confirmation prompt and proceed immediately
```

### SEE ALSO

* [jit migrate](jit_migrate.md)	 - Guided fix path for findings jit scan reports (name the file(s) to convert)

