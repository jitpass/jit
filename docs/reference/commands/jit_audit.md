## jit audit

Scan for plaintext secrets exposed on this machine (read-only)

### Synopsis

jit audit scans shell configs, .env files, credential files, MCP/AI-tool configs, private keys, IaC variable files, and suspicious filenames for plaintext secrets. Default behavior is strictly read-only: it never touches, encrypts, or rewrites a single file on disk. No real secret value is ever printed, only a masked preview.

```
jit audit [flags]
```

### Options

```
      --format string   output format: "text" (default), "markdown"/"md", or "ndjson" (default "text")
  -o, --output string   write the report to this file instead of stdout
      --score           print only the exposure score (e.g. "Exposure: 92/100 (CRITICAL)") and exit
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

