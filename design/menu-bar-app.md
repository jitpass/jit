# JitPass menu bar app

**Status: proposed (2026-09-16). Nothing built.** This document specifies the
app, the engine additions it needs, and the order in which they land so that
every step is reversible until the last one.

## Why

Three problems share one fix.

1. **Reach.** Every jit surface is the terminal. The developers who most need
   a credential broker are not all CLI-first, and a security tool nobody
   installs protects nobody.
2. **Unexplained prompts.** The Touch ID dialog is a bare `LAContext` sheet
   with one line of text. It cannot say who asked, why, what "deny" does, or
   how to stop it asking. Prompt fatigue is the most likely reason an
   installed user uninstalls.
3. **Secure Enclave.** `internal/secureenclave` is deferred because keychain
   persistence of an SE key needs a provisioning-profile entitlement that
   only an `.app` bundle can carry (`spike/secure-enclave/FINDINGS.md`,
   re-confirmed 2026-07-11). A bare Mach-O can never have it.

A menu bar app answers all three: it is a GUI, it is where a prompt can
explain itself, and it is the bundle the agent has to live in.

## What it is not

- **Not a new engine.** The Go binaries stay the product: `jit` and
  `jit-agent` do every read, decision, serve and write. The app is a client of
  the agent socket and nothing else. If the app process is killed, jit is
  unchanged.
- **Not mandatory.** Headless use, CI, build boxes and people who dislike menu
  bar icons keep the CLI-only tarball. No CLI code path may require the app.
- **Not a vault browser.** v1 shows names, states and events. It never
  displays a secret value. `jit vault get` stays in the terminal with its
  fresh Touch ID.
- **Not a TUI and not a local web page.** A TUI reaches only the audience the
  CLI already reaches and needs a framework `TECH_STACK.md` R1 rejected. A
  local web app opens a listening port on the machine whose whole point is a
  smaller surface, the reason `design/minting-broker.md` was narrowed.

## Shape

    JitPass.app/
      Contents/
        MacOS/JitPass              Swift, SwiftUI + AppKit, menu bar only (LSUIElement)
        Helpers/jit                Go, unchanged binary from the jit release
        Helpers/jit-agent          Go, unchanged; launchd points here (phase 2)
        Info.plist
        embedded.provisionprofile  phase 3, Secure Enclave entitlement

- **Language: Swift.** Every API the app needs (menu bar item, notifications,
  `LocalAuthentication`, `CryptoKit.SecureEnclave`, signing, entitlements) is
  one native call. Go GUI toolkits and WebView shells each add a large
  dependency and reach the same APIs through a bridge. Swift the language is
  portable; the frameworks are not, and jit is macOS-only by decision
  (`platform-scope-macos-only`), so that costs nothing.
- **Repository: separate, `jitpass/jit-app`, private at first.** Not a fork.
  It contains only the Swift project and pins a released jit version, which
  it downloads at build time and verifies against `checksums.txt` and the
  Developer ID signature the same way `jit upgrade` does. The Go module never
  imports it; CI here never sees it. Reverting the app is archiving that repo.
- **Identity.** Team `CZC6BH93GJ`, bundle id `com.jitpass.app`, decided once:
  the SE entitlement and keychain access group are keyed on it and changing
  either later orphans keys. The launchd label stays `com.jitpass.agent`.
- **One agent.** The app talks to the same socket path the CLI uses and runs
  the same protocol handshake (`Request.MinProtocol`, `Response` protocol
  number). A Homebrew CLI and the app on one machine share one agent, never
  two.

## What v1 shows

The dropdown, top to bottom. Each row is a socket op the CLI can also send.

| Row | Socket op | CLI equivalent |
|---|---|---|
| Lock glyph in the menu bar: locked / unlocked with countdown | `status` (polled) + `subscribe` | `jit service status` |
| Lock now / Unlock | `lock`, `unlock` | `jit lock`, `jit unlock` |
| Active grants: holder, profiles, expiry, serve count; Revoke | `grant_list`, `grant_revoke` | `jit grant list`, `jit grant revoke` |
| Last N events, live | `subscribe` | `jit audit -f` |
| Pending consent request with Allow / Deny (phase 4) | `consent_list`, `consent_answer` | none today; added for both |
| Open jit audit / doctor in Terminal | none | shell out |

Notifications, opt-in per kind: session locked (with why: idle, ceiling,
screen lock, sleep), grant ended, a **decoy was served** to a reader outside
any grant, a consent request denied N times in a row (the loop signal
`consentReason` already counts).

Nothing in the app decides anything. Revoke is the only mutating action and
it needs no auth today (`jit grant revoke` is unauthenticated by design:
reducing access is free). Unlock triggers the agent's own challenge.

## Engine additions

All additive. Each is a separate PR, useful to the CLI on its own, and stays
if the app is abandoned.

1. **`subscribe` op** (`OpSubscribe`). A long-lived connection on which the
   agent streams `SessionEvent` records as they happen, newline-delimited,
   same shape `history` returns. Peer is verified same-user like every other
   op. `jit audit -f` today re-reads a file; it moves onto this and gets
   sub-second latency for free. Bumps `Protocol` to 2; a client that sends
   `subscribe` to a protocol-1 agent gets the existing unknown-op error.
2. **Richer `status`.** Add `locks_at` (absolute), `lock_reason` of the last
   lock, `ceiling_at`, `consent_enabled`, `protocol`. `jit status` prints the
   new fields; no field is removed.
3. **Consent brokering ops** (phase 4 only): `consent_list` returns pending
   requests with the full `consentReason` line and strength; `consent_answer`
   carries a decision and scope. The engine's `consent.Prompter` gains an
   implementation that parks the request, notifies subscribers, and waits
   with the existing timeout, falling back to the `LAContext` dialog when no
   app is subscribed. `Undecided` on timeout stays deny. This is the only
   addition that touches a decision path, which is why it is last and
   optional.

Nothing else in `internal/agent` changes. `internal/consent` stays pure.

## Phases and how each reverts

| Phase | Lands where | Revert |
|---|---|---|
| 0. This doc + `subscribe` + richer `status` | `jitpass/jit` | Leave them; CLI-useful |
| 1. App v0.1: read-only dropdown, lock/unlock, grants, live events. Temporary cask `jit-app` in the tap, depends on the `jitpass` cask | `jitpass/jit-app`, tap | Deprecate the cask; `jitpass` cask untouched |
| 2. Fold `jit` and `jit-agent` into the bundle. `jitpass` cask installs the app and symlinks `jit` via a `binary` stanza. launchd plist points at the bundled agent. `jit upgrade` learns to replace a bundle when `selfpath` resolves inside one. Retire `jit-app` cask. Tarball stays as CLI-only | `jitpass/jit` release config, tap | One tap PR pointing the cask back at the tarball |
| 3. Secure Enclave wrapper, opt-in: `jit vault rekey --wrapper secure-enclave`, and the reverse `--wrapper keychain`. `keychainwrap` remains the default for new vaults | `jitpass/jit` | Users run the reverse rekey; default never moved |
| 4. Consent prompts brokered through the app when it is running | both | Delete the Prompter implementation; `LAContext` path is the fallback and never left |

Phase 2 is the first change to the shipped install path; it is one reviewed
PR. Phase 3's opt-in must ship with the reverse rekey tested end to end
before the flag is visible. Making Secure Enclave the default for new vaults
is a separate, later decision and the only one-way door in this plan.

## Security notes

- The app adds no new privileged path. It is a same-user socket peer, subject
  to the same peercred check as any jit process, and cannot do anything the
  CLI cannot.
- The app never receives a DEK or a plaintext. `wrap`/`unwrap` are not in its
  vocabulary and the agent could refuse them from a peer whose exec path is
  the app bundle, but that would be a process-name gate, which jit does not
  build; the real boundary is that the app never asks.
- `subscribe` streams the same records `history` already returns to any
  same-user peer; no new information is exposed.
- Bundling the agent moves its code-signing identity from a bare Mach-O to
  the app's signature. `verifyStagedSignature` and `upgradeTeamIDs` apply to
  the bundle exactly as they do to the binary today; a bundle cannot be
  stapled either, so the online notarization ticket story is unchanged.
- The CGo surface does not grow: Secure Enclave lands in
  `internal/secureenclave`, already one of the named packages, behind the
  existing `vault.KeyWrapper` interface.

## Open questions

- Does the app poll `status` or rely solely on `subscribe` plus a lock-state
  event? Proposed: subscribe, with a 30s poll as a liveness check.
- Sandbox: an App Sandbox entitlement would block the Unix socket in
  `~/Library/Application Support`. Proposed: not sandboxed, hardened runtime
  only, same as the CLI today.
- Whether the app should launch at login by default. Proposed: yes when
  installed via the app cask, since the agent already does, and one toggle in
  the dropdown turns it off.
