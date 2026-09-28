## jit scan review

Mark findings you checked as not live, so scan stops reporting them

### Synopsis

Mark findings you checked as not live: a real-looking key in a test file or a README. The file is scanned again to find them, and every finding on LINE (or in the whole FILE) is marked.

A mark matches the value in that file, not the line: moving the line keeps the mark, and a changed value is reported again. It stores a keyed hash of the value, never the value, in jit's own folder (scan-reviewed.json). That file is the only thing this writes; scanned files are never touched.

Copies of secrets jit already holds (deep scan's vault copies, AI agent caches) cannot be marked: redact or rotate them. `jit scan --unfiltered` shows marked findings again, tagged; `jit scan unreview` removes a mark.

```
jit scan review FILE[:LINE]... [flags]
```

### Examples

```
  jit scan review ./tests/fixtures.json:12
  jit scan review docs/README.md
  jit scan review --list
```

### Options

```
      --format string   output format: "text" or "json" (default "text")
      --list            list every mark: file, line and what was found, never a value
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit scan](jit_scan.md)	 - Scan for plaintext secrets exposed on this machine (read-only)

