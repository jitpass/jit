## jit audit

Scan for plaintext secrets exposed on this machine (read-only)

### Synopsis

jit audit scans shell configs, .env files, credential files, MCP/AI-tool configs, private keys, IaC variable files, and suspicious filenames for plaintext secrets. Default behavior is strictly read-only: it never touches, encrypts, or rewrites a single file on disk. No real secret value is ever printed, only a masked preview.

Exposure score

jit reports a 0-100 exposure score (EXPOSURE:) next to the categorical RISK LEVEL. It is computed entirely locally and deterministically:

  1. Sum a severity-weighted load over all findings: critical 30, high 15, medium 6, low 2, info 0. (info is detection-only, not an at-rest secret, so it adds nothing.)
  2. Add 40 for each finding that carries a production indicator (a "prod"/"production" token) or a public IP address, the same signals that escalate the whole scan to CRITICAL.
  3. Cap the total at 100.
  4. Clamp into the band of the scan's RISK LEVEL, so the number and the label can never disagree: clean 0, low 10-39, medium 40-64, high 65-84, critical 85-100.

Findings inside a jitpass playground checkout crossed during the scan are synthetic demo secrets, so they are excluded from every count and from the score (the report states how many were excluded and where). Run with --score to print just the score line and exit.

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

