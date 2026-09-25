## jit job run

Run an AI job and print its output, secret values hidden

### Synopsis

Ask the service to run an AI job. Its output is printed here with every
secret value replaced by [hidden: NAME], and jit exits with the job's own
exit code. A job approved to ask each time asks for Touch ID, naming who
asked.

This is how an AI tool in a terminal (Claude Code, Codex, Gemini CLI) runs
a job. It needs no MCP server: the tool already reaches the service.

```
jit job run NAME [flags]
```

### Options

```
      --format string   output format: text or json (default "text")
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit job](jit_job.md)	 - Let AI tools run approved scripts without seeing their keys

