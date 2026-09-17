## jit wrap list

Show wrapped tools and their shim health

```
jit wrap list [flags]
```

### Options

```
      --all                        with --format json: include every catalog tool, wrapped or not, with where it is installed
      --discover jit wrap <tool>   with --all: for each installed, unwrapped tool, look for its key where jit wrap <tool> would (config files, then the tool's own export command) and report only whether one exists and where
      --format string              output format: "text" (default) or "json" (default "text")
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit wrap](jit_wrap.md)	 - Wrap CLI tools so their tokens are injected just-in-time

