---
title: Reporting a vulnerability
description: How to report a security issue in jit - privately, please.
---

# Reporting a vulnerability

jit handles secrets. If you find a vulnerability, please report it
privately - not as a public GitHub issue.

The canonical policy lives in **[SECURITY.md](../../SECURITY.md)** (kept at
the repo root so GitHub's Security tab finds it). The short version:

- **Email** the maintainer at **jitpass@outlook.com**, or use **GitHub
  private vulnerability reporting** ([Security
  tab](https://github.com/jitpass/jit/security) → "Report a
  vulnerability").
- Include the affected component, a minimal reproduction, and - if
  relevant - which [documented boundary](./architecture.md) you believe is
  violated. Behavior matching a documented limit is expected, not a
  vulnerability, though a wrongly-stated boundary is absolutely worth
  flagging.
- jit is maintained by a single person, part-time; no formal SLA, but
  security reports get priority over everything else.
