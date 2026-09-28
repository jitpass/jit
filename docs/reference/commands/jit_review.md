## jit review

Mark scan findings you checked as not live, so scan stops reporting them

### Synopsis

Mark scan findings you checked as not live: a real-looking key in a test file or a README. The file is scanned again to find them, and the findings on LINE (or in the whole FILE) are marked; --only narrows that to the findings with these record ids.

A mark matches what the finding is about, not its line: moving the line keeps the mark, and a changed value is reported again. For a finding about a whole file, such as an env file's, that is every credential it holds, or the file's content, so any change reports it again. A mark stores a keyed hash, never a value, in jit's own folder (scan-reviewed.json). That file is the only thing this writes; scanned files are never touched, and `jit scan` itself still writes nothing.

Findings jit can fix (Protect), and copies of secrets jit already holds (deep scan's vault copies, AI agent caches), are not marked: protect, redact or rotate them. `jit scan --unfiltered` shows marked findings again, tagged; `jit unreview` removes a mark.

```
jit review FILE[:LINE]... [flags]
```

### Examples

```
  jit review ./tests/fixtures.json:12
  jit review docs/README.md
  jit review --list
```

### Options

```
      --format string                   output format: "text" or "json" (default "text")
      --list                            list every mark: its id, file, line and what was found, never a value
      --only jit scan --format ndjson   mark only the findings with this record id (repeatable), as jit scan --format ndjson prints them
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

