## jit unreview

Remove review marks, so scan reports those findings again

### Synopsis

Remove review marks: the ones --id names (as `jit review --format json` and `--list` print them), or every mark on FILE (on LINE, the line the finding was on when it was marked). The next scan reports those findings again.

```
jit unreview [FILE[:LINE]...] [flags]
```

### Options

```
      --format string   output format: "text" or "json" (default "text")
      --id strings      remove the mark with this id (repeatable)
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

