---
title: Blog editorial plan
description: Working document - editorial rules, cadence, and the post backlog for both tracks.
---

# Blog editorial plan

Working document, not a published page. The public landing page is
[index.md](./index.md).

## The one rule

**Every post must be worth reading by someone who will never install jit.**
Structure: ~90% genuinely useful analysis, then one honest closing section -
"what jit covers here, and what it doesn't." Naming what jit *doesn't* cover
is what buys credibility. If a draft reads as a wrapper around a pitch, cut
the pitch, not the analysis.

## Tracks

### Track 1 - The threat lens

Three rotating pillars:

1. **Incident breakdowns.** A real infostealer campaign or supply-chain
   attack, traced to the specific files and mechanisms it abused. Cite the
   original research (Wiz, Socket, SentinelOne, Datadog, etc.), link primary
   sources, never overstate. Timely: shareable for ~2 weeks after the news.
2. **"Where does X store your token?"** One tool per post: `gh`, `docker
   login`, `.npmrc`, kubeconfig, MCP configs, clipboard managers. Evergreen,
   search-friendly, maps to the [wrap coverage table](../wrap/index.md).
3. **Concepts.** Why user-level readability is the real boundary, what
   clipboard managers retain, TOCTOU on revealed files, why Keychain gating
   matters.

### Track 2 - Inside jit

Architecture, features, and rationale. Each post should teach a
*transferable* design idea (envelope encryption, the `credential_process`
protocol, PATH shims, crash-safe rotation) so it stands alone as an
engineering read - jit is the worked example, not the subject line's only
draw. Link deep into the [docs](../index.md) instead of re-explaining.

## Cadence

- Target: **biweekly**, alternating tracks. Go weekly only while a buffer of
  3-4 finished drafts holds.
- Write the first 3-4 posts *before* publishing the first one.
- A blog whose latest post is six weeks old reads as abandonment; a steady
  biweekly beats a broken weekly.

## Publishing & promotion

- Files live here as `YYYY-MM-DD-slug.md`, listed newest-first on
  [index.md](./index.md) with a track tag. The repo is the canonical home;
  every platform version links back to it.
- **Distribution channels: X and LinkedIn.** Both algorithms penalize bare
  external links, so each post ships as *native content* per platform, not a
  shared URL:
  - **X**: a thread (5-10 tweets) carrying the post's core argument - the
    hook, the 2-3 strongest facts, one screenshot or terminal capture - with
    the repo link in the final tweet.
  - **LinkedIn**: a self-contained ~200-300 word native post (the story +
    the takeaway), image attached, link in the first comment or at the end.
- **Every post needs at least one visual.** Terminal captures from the
  playground (audit output, a wrap in action, a decoy `.env`), or a simple
  diagram. Text-only posts underperform badly on both platforms.
- Incident posts must ship while the incident is still news (~2 weeks).
- Write the thread/LinkedIn versions alongside the post itself, not as an
  afterthought - the platform version *is* the reach; the repo post is the
  depth behind it.
- After the first post ships, link the blog from the README.

## Backlog

### Threat lens

1. **What an infostealer actually takes from a dev laptop** - anchor post;
   walk a real stealer's file-grab list (`.env`, `~/.aws/credentials`,
   browser tokens, `.npmrc`).
2. **Your `.npmrc` is a bearer token: anatomy of the 2025 npm worm attacks**
   - Shai-Hulud / Nx `s1ngularity`; postinstall scripts sweeping exactly the
   files `jit audit` flags.
3. **Where does the GitHub CLI store your token?** - starts the tool-audit
   series; then doctl, stripe, docker, MCP configs as follow-ups.
4. **Your clipboard manager remembers that password** - what clipboard
   history apps retain; ties to `vault get --copy` conceal/auto-clear.
5. **MCP configs are the new `.env`** - plaintext keys in `mcp.json` and
   desktop-app configs; timely and underexplored.

### Inside jit

1. **Why jit exists** - origin story; the audit of a working dev machine and
   what it turned up. Personal, honest, short.
2. **Getting started with jit in ten minutes** - narrative quickstart:
   audit → vault → agent → migrate; companion to
   [the quickstart](../getting-started/quickstart.md).
3. **What the vault actually offers** - envelope encryption, per-secret
   files, Touch ID gating, the agent boundary; companion to
   [security architecture](../security/architecture.md).
4. **How `jit wrap gh` works** - PATH shims, per-invocation injection, the
   ~25 ms overhead, why it survives scripts and subprocesses.
5. **Decoys by default: live-mounted `.env` files** - reveal windows and why
   the file on disk lies to whoever reads it uninvited.
6. **Crash-safe key rotation** - how `jit vault rekey` survives being killed
   mid-rotation; transferable pattern for anyone rotating master keys.
7. **What jit deliberately doesn't protect against** - the threat-model
   honesty post; likely the biggest trust builder of the set.
