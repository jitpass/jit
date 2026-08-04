## jit scan

Scan for plaintext secrets exposed on this machine (read-only)

### Synopsis

jit scan scans shell configs, .env files, credential files, MCP/AI-tool configs, private keys, IaC variable files, and shell history for plaintext secrets. Default behavior is strictly read-only: it never touches, encrypts, or rewrites a single file on disk. No real secret value is ever printed, only a masked preview.

Shell history is the surface the others miss by construction: a credential gets there by being typed, so it never sits in a file whose name announces it. ~/.zsh_history, ~/.bash_history, ~/.sh_history, ~/.history, fish history and $HISTFILE are all swept.

Scanning specific paths

Pass one or more files or directories to scan only those, instead of the whole machine: `jit scan ./project token.txt`. A directory is walked with the same name-based rules as the full scan. A file you name explicitly is classified regardless of its name — a shell/env/MCP/IaC/history file is routed to its own scanner (so a named history file still reports line numbers), and anything else is swept for known vendor tokens and JWTs, so `jit scan token.txt` catches a bare token the full scan's naming rules would miss. Named paths never pull in the fixed machine-wide credential stores (~/.aws, ~/.ssh, …); symlinks are not followed.

Exposure score

jit reports a 0-100 exposure score next to the categorical risk level (the report's `✗ CRITICAL — exposure 85/100` banner). It is computed entirely locally and deterministically:

  1. Sum a severity-weighted load over all findings: critical 30, high 15, medium 6, low 2, info 0. (info is detection-only, not an at-rest secret, so it adds nothing.)
  2. Add 40 for each finding that carries a production indicator (a "prod"/"production" token) or a public IP address, the same signals that escalate the whole scan to CRITICAL.
  3. Cap the total at 100.
  4. Clamp into the band of the scan's risk level, so the number and the label can never disagree: clean 0, low 10-39, medium 40-64, high 65-84, critical 85-100.

Run with --score to print just the score line and exit.

Exit status

By default jit scan always exits 0: finding secrets is its job, not an error, and a read-only report shouldn't fail a shell. To use it as a GATE (a pre-commit hook, a CI step), give it a threshold with --fail-on <level>: the scan exits 2 when its risk level is at or above that level, e.g. `jit scan --fail-on high`. --fail-on any trips on anything that isn't clean.

The status is 2, never 1, so a tripped gate is distinguishable from the scan itself failing (a bad flag, an unreadable path), which stays 1. The report is always written in full first — the gate never costs you the findings that explain it. --fail-on works with --score too.

```
jit scan [path...] [flags]
```

### Options

```
      --fail-on string   exit 2 when the scan's risk level is at or above this: critical, high, medium, low, or any (default: always exit 0)
      --format string    output format: "text" (default), "markdown"/"md", or "ndjson" (default "text")
      --full             print the full finding inventory (categories, severities, every file and line) instead of the coverage summary
  -o, --output string    write the report to this file instead of stdout
      --score            print only the exposure score (e.g. "Exposure: 92/100 (CRITICAL)") and exit
      --unfiltered       show findings jit normally judges to be settings, paths, browser-public build variables or unfilled template values; each is tagged [unfiltered] with the rule that hid it, so one run audits what the filters are hiding
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

