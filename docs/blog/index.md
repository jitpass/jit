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
deep dives (the vault's envelope encryption, the service boundary, live-mounted
files), feature walkthroughs, and honest notes on what jit deliberately does
not protect against.

## Posts

- **2026-07-27** · [They spent $53,000 of your money to make $800](./2026-07-27-fifty-three-thousand-dollars.md) - a leaked AWS key, ninety seconds, and one night of mining, reconstructed from documented incidents. `threat-lens`
- **2026-07-26** · [The malware never read your `.env`. It asked your agent to.](./2026-07-26-the-agent-read-it-for-you.md) - SANDWORM_MODE plants a rogue MCP server, hides its instructions in the tool descriptions, and lets your assistant do the reading. `threat-lens`
- **2026-07-20** · [What an infostealer actually takes from a dev laptop](./2026-07-20-what-an-infostealer-takes.md) - the real file-grab list from AMOS, s1ngularity, and Shai-Hulud, and the paper-thin boundary that makes it all work. `threat-lens`
- **2026-07-18** · [docker login stores your password in base64 - and the 4-verb protocol that fixes it](./2026-07-18-docker-login-base64.md) - who has plaintext registry logins right now, how Docker's credential-helper protocol works, and what jit v0.16 does with it. `inside-jit`

<!--
Post entry format, newest first:
- **YYYY-MM-DD** · [Title](./YYYY-MM-DD-slug.md) - one-line hook. `threat-lens` | `inside-jit`
-->
