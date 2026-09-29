# Plan: one question, one Touch ID (the consent side panel)

Status: proposed 2026-09-29, awaiting approval.
Mockup: https://claude.ai/artifact/Jf2B4bFvmgYjRS5MHpiKWa (built on the
JitPass design system). Spike: `spike/consent-sync/FINDINGS.md`, PASS on all
four checks.

## The problem

When a program asks jit for a secret with JitPass running, the user answers
twice. The app's consent sheet asks first, and its Allow grants nothing
(`internal/agent/consentbroker.go`: "allow does not grant anything"). Then
the Touch ID dialog asks the same question. A locked vault plus a gated
credential makes that four steps: sheet, Touch ID, sheet, Touch ID. The
menu bar app design names prompt fatigue as the most likely reason a user
uninstalls (`jit-app docs/design/menu-bar-app.md`).

## The change

- The Touch ID appears at once.
- The menu bar panel opens by itself beside it, without taking focus. The
  request sits at the top of the panel as an **Asking block**, the place the
  design system keeps for it.
- The block shows the consent sheet's facts in the engine's exact words,
  with a Deny button and no Allow.
- The fingerprint allows the request. Deny, in the panel or on the dialog,
  refuses it.
- With no app running, the Touch ID appears alone, as it does today.

This reverses one part of the 2026-09-25 decision "One sentence, not two"
(`design/agent-jobs.md`): the sheet goes. The part that decision was built
on still holds. The Touch ID dialog stays self-contained, is still what
approves, and its sentence is still what the audit records.

## Why it is safe

- The broker's Allow never granted anything, and any same-user process
  could send one. Removing it removes no protection.
- The new "shown" signal grants nothing either. It only shortens a wait of
  at most 250 ms, and a process that fakes it gains nothing.
- Deny only reduces access. Today any process can already refuse a request
  it did not receive; cancelling a dialog is the same power.

## What the spike proved (FINDINGS.md)

- Invalidating the `LAContext` from another thread takes the dialog down:
  31 ms on the keychain path, 42–50 ms on the Secure Enclave path.
- A click on a non-activating panel reaches it while the dialog is up.
- The dialog appears 121–152 ms after the panel. About 120 ms of that is
  macOS drawing its own dialog.
- The panel took focus in none of the 11 runs.
- A Deny from the panel is `LAError -9` (app cancel); Cancel on the dialog
  is `-2` (user cancel). The audit can tell them apart.

## Work, in order

Each step is its own PR. Steps 2 and 3 touch the vault-key code (the
fetchers of both key stores), so they get full review rounds. The others
get tests and CI.

### 1. jit: the two quick fixes (branch `fewer-prompts`, started)

These stand alone and cut prompts with or without the panel.

- **Fix 1.** A consent prompt on a locked vault also unlocks it. Today
  `gateConsent` → `forceDisclosedChallenge` fetches the vault key and wipes
  it, then `ensureUnlocked` asks again.
  - The sentence gains "unlock the vault and …" only when the vault is
    locked, the unlock cooldown is not running, and the request's next step
    needs the session. That covers the consent gate on an unwrap and
    `jit run --with`. It does not cover grants, job runs, or `--trust`,
    where opening the session would give more than was asked.
  - The key opens the session only if the session is still locked when the
    Touch ID is approved, checked under `challengeMu`.
  - The app's `ConsentRequest.isUnlock` reads the prefix "unlock the
    vault", so it needs a matching purpose line.
- **Fix 2.** An approval slides while it is used. Today
  `consent.Engine.remember` sets a fixed `now + sessionTTL` and `lookup`
  never extends it, while the session itself slides, so an active loop is
  asked again every 5 minutes. A hit extends it to match the session. It is
  already cleared on lock.

### 2. jit: Touch ID that can be cancelled (vault-key code, full review)

- `agent.MEKFetcher` gains an optional interface:

  ```go
  type CancelableFetcher interface {
      FetchMEKCancel(reason string, cancel <-chan struct{}) ([]byte, error)
  }
  ```

  It is implemented by `keychainwrap.Wrapper` (around `kw_challenge`) and
  `secureenclave.Wrapper` (around `se_open`, whose `LAContext` already rides
  on the key query). A closed `cancel` invalidates the context in flight.
  A cancel that arrives before the prompt starts is kept and applied the
  moment it does (the spike's `arm`/`cancel_prompt`).
- Errors map to two causes: `-9` becomes "denied in JitPass", and `-2`
  becomes "cancelled on the Touch ID". Anything else stays a failure, as
  today.
- Only the dialog can be cancelled. Reading the keychain item and opening
  the vault key afterwards are never interrupted halfway.
- Tests use a fake fetcher that honours `cancel`, with negative controls: a
  fetcher that ignores the cancel must fail them. The hardware half extends
  `scripts/se-test.sh` with an attended cancel run on a TEST-ONLY enclave
  key.

### 3. jit: the broker stops waiting for Allow (vault-key code, full review)

- The `pending` event gains `touch_id_follows: true`. That flag tells the
  app to show the Asking block, not the sheet.
- New op `consent_shown {consent_id}`, prompt-free, like `consent_answer`.
- `brokerConsent` in this mode:
  1. Publish the request.
  2. Wait at most 250 ms (`shownWait`) for `consent_shown`, or for a deny.
  3. A deny inside the wait refuses with no dialog, as today.
  4. Then raise the Touch ID through `FetchMEKCancel`. A `consent_answer
     deny` during the prompt closes `cancel`.
  5. A late `allow` (from an older app) is a no-op.
  6. After the fetch returns, check the withdrawal again. `FetchMEKCancel`
     lets an approval that wins the race stand (a finger touch a few
     milliseconds after the Deny), so the broker must still refuse and wipe
     the key rather than open the session or serve the secret. A Deny is
     never overtaken by a late touch. (Raised by the step 2 review.)
- `brokerWait` (90 s for an answer) no longer applies in this mode. The
  Touch ID's own 120 s timeout bounds it.
- The dialog's sentence: see D1.
- The refusal backoff counts a panel Deny exactly as it counts today's
  broker deny.
- Tests:
  - the wait honoured, and the prompt starting at the cap with a silent
    broker;
  - no wait at all without a broker;
  - a deny before, during, and after the prompt, and a deny that loses the
    race to an approval (still refused);
  - the audit's two causes;
  - an old-style `allow` ignored.

### 4. JitPass: the Asking block (tests and CI; UI per the mockup)

- `ConsentRequest` reads `touch_id_follows`.
- On a request carrying it:
  - add it to the model;
  - open the menu bar panel as a non-activating panel (the spike's flags:
    `.nonactivatingPanel`, `becomesKeyOnlyIfNeeded`, level `.statusBar`);
  - send `consent_shown` once the panel is drawn.
- Requests from the app's own pid, or from a `jit` it started, get
  `consent_shown` at once and no block. That replaces today's auto-allow.
- The block:
  - the engine's title and sub line;
  - Command / Launched by / Identified / Asked;
  - one note line;
  - Deny, sent as `consent_answer deny`.
- AI job runs keep their own facts (folder, command, secrets) in the same
  block.
- On the outcome event, the block turns into "Allowed …" or "Denied …".
  The panel closes after 3 seconds, but only if the app opened it itself.
  A panel the user opened stays open.
- The sheet (`ConsentView`, `consentWindow`, `JobRunConsent`'s sheet) stays
  only for a request without the flag: an older jit. See D2.

### 5. Design system (after approval of the words)

- Rewrite the ConsentSheet component page as the Asking block.
- Add the Asking block to MenuPanel's README.
- The sheet's three notes are "fixed copy". With no Allow, the first note
  becomes untrue. The block keeps one line: "Deny cancels the Touch ID: the
  program gets an error and no secret. Both answers are recorded in the
  audit."

### 6. Release

1. jit release (steps 1–3).
2. The app's `jit.version` bump and step 4.
3. One app release.
4. Before tagging: a signed test build, in which the spike's timings are
   measured again with the real helper under launchd and the real panel.

## Decisions for Meni

- **D1. The Touch ID sentence.** *Recommended:* the full sentence, always.
  The short "confirm: …" form existed because an Allow click came first.
  With the panel appearing alongside, "confirm" reads as though something
  was already confirmed.
- **D2. The old sheet as a fallback.** *Recommended:* keep it for one
  release, for a request without `touch_id_follows`, then delete it. The
  service is the app's own bundled jit, so a mismatch should be rare, but a
  fallback costs little.
- **D3. Auto-close.** *Recommended:* 3 seconds after the answer, only for a
  panel the app opened.
- **D4. Unusual requests.** *Recommended:* an amber line in the block for a
  program found by a process scan, or one refused before, rather than
  bringing back a two-step sheet.
- **D5. Order.** *Recommended:* ship step 1 on its own first. It helps
  today, without the app change.
