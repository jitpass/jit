---
title: Security self-reviews
description: jit reviews its own code for vulnerabilities on a cadence and publishes the results, limits included.
---

# Security self-reviews

jit handles secrets, so we review the code for vulnerabilities on a
cadence and publish the results here, including the honest limits, not
just the clean parts.

| Date | Type | Report |
|------|------|--------|
| 2026-07 | Internal review: AI-assisted (Claude Opus 4.8) + on-host verification | [2026-07.md](./2026-07.md) |

An independent third-party audit, if and when one happens, will be listed
here and labeled as such; internal reviews are not a substitute for one.

To **report** a vulnerability, see [Reporting](../reporting.md) (private
disclosure). For what jit deliberately does *not* defend against, see the
[security architecture](../architecture.md) and each review's "known,
accepted limitations" list.
