---
title: jit blog
description: Essays on where dev-machine secrets leak, how attackers take them, and how jit is built to stop it.
---

# jit blog

Writing in two tracks:

**The threat lens** - what actually goes wrong on developer machines.
Breakdowns of real infostealer campaigns and supply-chain attacks, audits of
where popular tools store your tokens, and the concepts behind the "readable
by anything running as your user" boundary. These posts are written to be
useful even if you never install jit.

**Inside jit** - how jit works and why it's built that way. Architecture
deep dives (the vault's envelope encryption, the agent boundary, live-mounted
files), feature walkthroughs, and honest notes on what jit deliberately does
not protect against.

## Posts

- **2026-07-20** · [What an infostealer actually takes from a dev laptop](./2026-07-20-what-an-infostealer-takes.md) - the real file-grab list from AMOS, s1ngularity, and Shai-Hulud, and the paper-thin boundary that makes it all work. `threat-lens`

<!--
Post entry format, newest first:
- **YYYY-MM-DD** · [Title](./YYYY-MM-DD-slug.md) - one-line hook. `threat-lens` | `inside-jit`
-->
