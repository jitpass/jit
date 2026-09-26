## jit job allow

Approve a command as an AI job (asks for Touch ID)

### Synopsis

Approve COMMAND, run in this folder, as the AI job NAME. jit shows the
whole job, then asks for Touch ID. Nothing runs now.

--profile names the profile whose secrets the job gets. With one profile
in this folder's .jit/profiles it is picked for you. Every value is hidden
in the output unless you name it with --show: use that for configuration
that appears in what the script prints, never for a key.

--output names a folder the job writes into. New files there are reported
to the tool by path, and changes there never stop the job.

Some commands are refused because they hand the values straight back:
env, cat, echo, or a program written into the command (python -c,
sh -c, node -e). Save it as a file and approve that file.

--ask never is refused when jit cannot fingerprint what the program
loads: a launcher that picks the interpreter when it runs (uv run, npx,
a pyenv shim), or ruby and other interpreters whose libraries it does
not read. Approve the interpreter itself: .venv/bin/python script.py.

```
jit job allow NAME [--profile NAME] [--show VAR] [--output DIR] -- COMMAND [ARGS...] [flags]
```

### Examples

```
  jit job allow notion-export --show NOTION_WORKSPACE \
    --output ~/code/scripts/notion/out \
    -- .venv/bin/python export_pages.py
```

### Options

```
      --ask string           each-time (Touch ID per run) or never (runs unasked until you remove it) (default "each-time")
      --description string   one line an AI tool sees in the job list
      --dry-run              check the job and show what approving it would do, without asking or keeping anything
      --output stringArray   a folder the job writes into (repeatable)
      --profile string       profile whose secrets the job gets
      --replace              approve over an existing job of the same name
      --show stringArray     a variable whose value may appear in the output (repeatable)
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit job](jit_job.md)	 - Let AI tools run approved scripts without seeing their keys

