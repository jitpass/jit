## jit scan unreview

Remove review marks, so scan reports those findings again

### Synopsis

Remove the review marks on FILE (on LINE, the line the finding was on when it was marked). The next scan reports those findings again.

```
jit scan unreview FILE[:LINE]... [flags]
```

### Options

```
      --format string   output format: "text" or "json" (default "text")
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit scan](jit_scan.md)	 - Scan for plaintext secrets exposed on this machine (read-only)

