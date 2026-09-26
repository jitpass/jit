## jit job

Let AI tools run approved scripts without seeing their keys

### Synopsis

An AI job is a command you approve once, with the secrets it needs.
An AI tool (Claude Code, Codex, Claude Desktop) runs it by name. The jit
service runs it on this Mac and hands back the output with every secret
value hidden, so the tool never holds a key.

Two things keep an approval meaning what you approved. jit fingerprints
the job's folder and what its program loads from outside it (Python's
standard library and packages, the native libraries it links), so a
script, a library or a profile edited afterwards stops the job until you
approve it again. And the secrets are fixed at approval: editing the
profile later never changes what the job gets.

```
jit job
```

### Examples

```
  cd ~/code/scripts/notion
  jit job allow notion-export -- .venv/bin/python export_pages.py
  jit job run notion-export
  jit job list
  jit job remove notion-export
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime
* [jit job allow](jit_job_allow.md)	 - Approve a command as an AI job (asks for Touch ID)
* [jit job list](jit_job_list.md)	 - Show the approved AI jobs and whether each can run
* [jit job remove](jit_job_remove.md)	 - Remove an AI job now
* [jit job run](jit_job_run.md)	 - Run an AI job and print its output, secret values hidden

