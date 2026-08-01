---
name: qa-release
description: Run jit's pre-release QA — a team of QA-engineer subagents (functionality, integrations, UX, bug-hunting, code review) that exercise a release candidate on this real Mac and hand back a consolidated release-readiness report. Invoke when the user says "test/QA release N", "check the build before we ship", "run the release QA", or "/qa-release". Attended (Touch ID). Not CI.
---

# jit pre-release QA orchestrator

You are running jit's pre-release QA as the lead of a QA team. The shared charter is
`docs/testing/pre-release-playbook.md` — read it. The mechanical helper is
`scripts/pre-release-live-test.sh`. The QA engineers are the `jit-qa-*` subagents. Your job:
pre-flight the release candidate, dispatch the team, consolidate their findings, and deliver one
release-readiness verdict. This is attended — the user is present to approve Touch ID.

## Safety (the whole team obeys; you enforce)
jit has ONE machine-global vault and no isolation. Everything runs against the user's REAL vault.
- Snapshot `jit vault list` + `jit status` NOW and record it. The run must end back at that baseline.
- All test secrets are namespaced `jit-e2e`; real OS files touched (`~/.aws`, `~/.docker`,
  `~/.gitconfig`, shell rc) are backed up and restored by the agent that touches them.
- NEVER destroy the real vault except the deliberate export-first delete drill on a mount-free vault.

## Step 1 — Pre-flight (you, main thread)
1. Identify the RC binary (a `JIT_BIN` the user gives you, or build HEAD/the tag with the version
   ldflag). Install it **atomically** — never `cp` over the running binary (SIGKILL 137); use
   `cp … .jit.new && mv -f … jit` then `jit service restart`.
2. Verify the swap: `jit service status` — **service build must equal CLI build**. Abort and report
   if not (a stale service is a release blocker on its own).
3. `jit doctor` baseline; record `jit vault list`/`status`. Determine the prev release tag
   (`git tag --sort=-creatordate | head`) to hand the code reviewer.

## Step 2 — Fast mechanical baseline (you)
Run `JIT_BIN=<rc> scripts/pre-release-live-test.sh --os-creds --destructive`. Read the summary;
each `✗` is a candidate finding. Confirm it ends "vault returned to baseline". This is coverage
insurance, not the QA itself.

## Step 3 — Dispatch the QA team
Coordinate around the single shared vault:
- **Wave A — parallel (read-only / read-mostly):** launch `jit-qa-code` (pass the diff range
  `<prev-tag>..HEAD`), `jit-qa-ux`, and `jit-qa-docs` together. They don't fight over vault state.
- **Wave B — sequential (vault-mutating):** run `jit-qa-functionality`, then `jit-qa-integrations`,
  then `jit-qa-bughunter`, one at a time. They each create `jit-e2e` secrets, mounts, and
  (functionality) may run the delete drill — running them in parallel would corrupt each other's
  vault state. Each self-cleans and restores baseline before the next starts.

Pass every agent the RC binary path (`JIT_BIN`) and remind it: namespace `jit-e2e`, back up any
real OS file, restore baseline. Wave B agents produce Touch ID prompts — the user approves them.

(If the user asks for a quick check rather than a full gate, run a subset — e.g. just
`jit-qa-functionality` + `jit-qa-integrations` — and say so in the report.)

## Step 4 — Consolidate
Collect every agent's findings plus the script summary. Dedup (multiple agents may hit the same
issue), merge severities (take the highest), and rank. Cross-check against the playbook's
known-gotcha watchlist (§7) — a regression there is elevated.

## Step 5 — Restore & verify
Confirm the vault is back to the Step-1 baseline (`jit vault list`/`status` match) and any real OS
files/TTL were restored. If anything leaked, clean it and note it.

## Step 6 — Deliver the verdict (playbook §9 template)
```
## jit <version> pre-release QA — <date>
Verdict: SHIP / SHIP WITH NOTES / DO NOT SHIP
Coverage: <agents run; script default/full; playground yes/no; delete drill yes/no>
Findings (deduped, most severe first):
  [BLOCKER] … — repro — expected vs actual — (found by: agent)
  [MAJOR]  …
  [MINOR]  …
  [NIT]    …
Regressions vs <prev tag>: <none | …>
State: vault restored to baseline ✓ / ✗
```
Be honest about coverage — never imply a surface was tested if no agent reached it. Recommend
SHIP only if there are no BLOCKER/MAJOR findings and the vault returned to baseline.
