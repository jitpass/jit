# Security Policy

jit handles secrets. If you find a vulnerability, please report it privately — not as a public GitHub issue.

For our own security posture — what jit protects against, what it doesn't yet, and the findings from our reviews — see [security/](./security/).

## Reporting a Vulnerability

Report privately through either channel — please **don't** open a public issue or PR:

- **Email** the maintainer at **jitpass@outlook.com** — works anytime, no GitHub account needed.
- **GitHub private vulnerability reporting** (available once this repo is public): go to the [Security tab](https://github.com/jitpass/jit/security) and click **"Report a vulnerability"** to open a private advisory thread.

Either way, the report stays private between you and the maintainer — no public disclosure until it's resolved.

Please include, if possible:
- The affected component (vault, injection mechanism, audit scanner, etc.)
- A minimal reproduction
- If relevant, which documented limitation you believe is violated (see the [security architecture](./docs/security/architecture.md) and the "known, accepted limitations" list in each [published review](./docs/security/self-reviews/index.md)) — this helps distinguish a new finding from an already-documented, accepted one. A report describing behavior that matches a documented boundary (e.g. "the target process can read its own injected secret") is expected behavior, not a vulnerability, though it's still worth flagging if you think the boundary itself is stated incorrectly.

## Response Expectations

jit is currently maintained by a single person, part-time. There's no formal SLA, but security reports get priority over everything else in progress.

## Scope

Only this repository's code (`cmd/`, `internal/`) is in scope. Code under `spike/` is explicitly throwaway/exploratory and not production code — issues there aren't a priority unless they reveal a flaw in an assumption the real implementation depends on.
