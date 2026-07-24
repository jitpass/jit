# Voice

One writing voice across the README, the docs, and the landing page. This is the
standard they all check against.

## The brief

Write to a smart engineer who is skeptical of security tools. Lead with their
real problem in their own filenames. Prove each claim with an annotated command,
not an adjective. State the limits plainly. Reassure that nothing breaks and
everything is reversible.

## The register

- **Peer to peer.** Second person, engineer to engineer. "you", never "users".
- **Concrete over abstract.** Real files (`~/.aws/credentials`, `.npmrc`), real
  tools (aws, gh, terraform), real attacks (`curl | sh`, a sketchy `npm install`,
  AMOS). No "enterprise-grade", "military-grade", "zero-trust" filler.
- **Threat-first.** Frame value as "what does an attacker get?" The answer is a
  decoy. That through-line sells better than a feature list.
- **Show, do not tell.** An annotated command block proves the point; the prose
  only sets it up. The inline `# comment` does the teaching.
- **Honest.** Name the limits (macOS-only, best-effort, still in development).
  Under-claiming is what earns trust in security. Never oversell.
- **Active voice, present tense.** "jit moves each secret", "the shim injects".

## Hard rules

- **No em dashes.** Use colons, commas, parentheses, or a spaced hyphen. This is
  not a preference, it is the rule. (The landing's `&mdash;` is the one place we
  currently break it.)
- Inline `code` for every command, file, and variable. **Bold** for key terms
  only, sparingly.
- Short sentences. Fragments for emphasis are fine ("On disk there's now a
  decoy."). Cut every word that does not earn its place.

## Same voice, different format

The voice above is shared. The shape is not, because the jobs differ.

- **README / docs** onboard a reader who is already here, top to bottom. Linear
  prose and reference tables are fine. You can open with a limitation.
- **Landing** hooks a cold skimmer in about five seconds and pushes one action.
  So: big hero, scannable cards, a sharper first line, CTAs, and even shorter,
  punchier copy. Do not lead a landing with your limitations; put them lower.

## Smell test

Before shipping a paragraph, ask:

1. Could a competitor's marketing page have written this sentence? If yes, cut or
   make it concrete.
2. Is there an em dash? Remove it.
3. Is there a claim without a command, file, or number behind it? Back it or drop
   it.
4. Can this be shorter? It almost always can.
