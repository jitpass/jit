# Spike Findings: Notarization End-to-End Probe (gate for Homebrew distribution)

**Question:** does Apple's notary service now reliably process this account's
submissions to a verdict, and does the resulting ticket actually clear a
*quarantined*, *unstapled* bare Mach-O through Gatekeeper — the exact
situation a Homebrew-cask user is in?

**Why this exists:** notarization was dropped from `.goreleaser.yml` (commits
`9177b38`, `2d45149`) after the account's notary service left 8 of 9
submissions hanging "In Progress" indefinitely — including shipped release
builds, which held releases hostage for days. Apple support case
20000125465695 (2026-08-01) established this is account-side: even a trivial
hello-world Mach-O hangs, authentication works, and the artifact signature is
valid. Every self-fixable cause is eliminated — all agreements were verified
accepted (Program License Jul 30, Developer Agreement Jul 29; Paid Apps is
App-Store-only), so this is fresh-account notary provisioning on Apple's
side. It also appears *intermittent*, not binary: on 2026-08-01 the service
partially recovered (one probe went Accepted with ~40min turnaround), yet the
shipped v0.70.1 build's own submission still never reached a verdict — its
ticket was absent from Apple's DB hours after publish. That mix is exactly
why the gate below demands consistency across days, and why this spike is the
cheap, repeatable way to detect when the condition truly clears — **before**
re-wiring the release and brew paths around notarization and discovering
mid-release that it still hangs.

## Method

A trivial Go Mach-O (any failure is therefore account/service-side, never
artifact-side), signed with **quill** — the same signer goreleaser's
`notarize.macos` path embeds, with the same full-chain `.p12` — submitted via
`xcrun notarytool` with a bounded `--wait`. `notarytool` rather than quill
for the submission for two reasons: it surfaces `history` and `log`, which is
where the diagnosis lives (the stuck condition was already shown to be
tool-independent), and it refreshes its auth tokens while waiting — the
goreleaser/quill path mints one JWT of `timeout + 2m` lifetime, which is the
401 trap that broke v0.69/v0.70 and caps any quill-side wait at ~18m.

On **Accepted**, the part brew actually depends on is verified explicitly:
jit ships a bare Mach-O, which cannot be stapled, and Homebrew quarantines
cask downloads — so a cask user's first run depends on Gatekeeper fetching
the notarization ticket online. The probe simulates that user: it sets
`com.apple.quarantine` on the signed binary, asks `spctl --assess` for a
verdict (expecting `Notarized Developer ID`), and executes the quarantined
copy.

Two ways to run it:

- **CI (normal path):** `gh workflow run notarize-spike.yml` — uses the same
  repo secrets as `release.yml`, so a green run means the release path would
  have notarized. `-f mode=history` lists recent submissions and their
  statuses without submitting anything new (also shows whether the old stuck
  submissions from July/August ever resolved).
- **Locally** on a machine that has the keys: set `QUILL_SIGN_P12`,
  `QUILL_SIGN_PASSWORD`, `NOTARY_ISSUER_ID`, `NOTARY_KEY_ID`, `NOTARY_KEY`
  and run `zsh spike/notarize-e2e/run.sh` (needs `quill` on PATH).

Exit codes: `0` Accepted + Gatekeeper pass · `1` Invalid (artifact verdict,
log dumped) · `2` stuck In Progress past the timeout (the known condition) ·
`3` Accepted but Gatekeeper rejected the quarantined copy — a state that
would break brew users even with notarization nominally "working", hence its
own code.

## Acceptance criteria (gate for un-reverting)

All of, before touching `.goreleaser.yml` or the cask:

1. **3 consecutive exit-0 runs across at least 2 different days.** One
   Accepted proved nothing last time (1 of 9), and the failure mode is
   intermittent-by-day, not per-artifact.
2. Verdicts arrive well inside 15m, not at the timeout edge. This criterion
   is load-bearing: goreleaser's quill path cannot wait longer than ~18m (the
   single-JWT 401 trap), so if Apple's steady-state turnaround is the ~40min
   seen on 2026-08-01, `wait: true` is off the table and the release instead
   needs `wait: false` plus an automated fail-closed post-publish verify —
   the v0.70.1 lesson, where wait-free publish shipped a build whose
   submission never completed.
3. The Gatekeeper leg passes each time (`Notarized Developer ID` + the
   quarantined copy executes).

Then re-add, in one change: the `notarize:` block (shape of `08e0b7d`, with
the `timeout: 15m` JWT lesson from `77cc73f`), and the `homebrew_casks` block
**without** the quarantine-strip hack `2d45149` removed.

## Results

| Date | Run | Submission id | Time to verdict | Status | Gatekeeper | Exit |
|---|---|---|---|---|---|---|
| 2026-07-30 → 08-01 | baseline (pre-spike) | 7 ids in support case | never (>2 days) | In Progress | n/a | — |
| 2026-08-01 | manual probe (pre-spike) | — | ~40min | Accepted | not checked | — |
| 2026-08-01 | v0.70.1 release build | — | never | In Progress | rejected (quarantined copy blocked) | — |
| _fill in per run_ | | | | | | |

**Verdict: pending** — the spike is built but blocked on Apple resolving the
account-side condition (or the agreements step completing). Do not
re-litigate the tooling: signing, auth, and the JWT timeout are all known
good.
