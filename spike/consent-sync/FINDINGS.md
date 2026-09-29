# Spike: the consent side panel and Touch ID, in step

Question: can the menu bar panel replace the two-step consent sheet (sheet,
then Touch ID) with one step? In the proposed design the service no longer
waits for an Allow. It sends the request, waits at most 250 ms for the panel
to say "shown", then raises the Touch ID at once, and the panel's Deny
cancels the dialog. Mockup: https://claude.ai/artifact/Jf2B4bFvmgYjRS5MHpiKWa

Four things had to hold:

1. The service can take down a Touch ID dialog that is already on screen,
   on both of jit's paths: keychain `evaluatePolicy`, and a decrypt with a
   Secure Enclave key that requires user presence.
2. A click on the panel's Deny works while that dialog is up.
3. The panel and the dialog appear close enough together to read as one
   moment.
4. The panel never takes focus from the dialog.

Environment: macOS 27.0, Apple Silicon, Go 1.26.4. Binaries were ad-hoc
signed and run from Claude Code's `!` shell on 2026-09-29. The service half
(`main.go` + `prompt.m`) stands in for jit's service and the panel half
(`panel/main.swift`) for JitPass, over a unix socket. Every dialog was real.
Nothing opened the vault, read the keychain or talked to the running
service. Each prompt used an ephemeral enclave key made for it alone.
`run.sh` drives the scenarios.

## Results (PASS on all four)

| Run | Path | What happened | Measured |
| --- | --- | --- | --- |
| A1 | enclave | panel denies 1.5 s in | dialog gone **50 ms** after the deny; `LAError -9` (app cancel) |
| A2 | keychain | panel denies 1.5 s in | dialog gone **31 ms** after the deny; `-9` |
| A3 | enclave | panel never says "shown" | prompt started at **264 ms**, the 250 ms wait running out |
| A4 | enclave | no panel at all | prompt started at **14 ms** |
| B1–B3 | enclave | approved | dialog **127, 130, 128 ms** after the panel |
| C1 | enclave | Cancel pressed on the dialog | `LAError -2` (user cancel) |
| D1 | enclave | **a real click on the panel's Deny** with the dialog up | dialog gone **42 ms** after the click; `-9` |
| all 11 | both | focus check 300 ms after the panel showed | panel took focus: **false** every time |

The gap between the panel and the dialog was 121–152 ms on every run where the watcher
found the dialog (9 runs), and the panel always came first. It breaks down as:

- the stand-in panel on screen about 120 ms after the request;
- the service raising the prompt about 9 ms after "shown";
- macOS drawing its dialog about 120 ms after the prompt started.

The first part is the stand-in's cold start (it builds its window from
nothing). The real app keeps its panel ready, so it will be faster. The last
part is macOS's own and does not change, so about 0.12 s between the two is
the floor, with the panel first.

## What the design can rely on

- **Cancel works on the enclave path the vault uses.** Invalidating the
  `LAContext` from another thread takes the dialog down within 50 ms. The
  context rides on the key (`kSecUseAuthenticationContext` in the key's
  attributes). jit's `se_open` already builds its `LAContext` and passes it
  in the key query, so the production change is to keep a handle to that
  context while the prompt is up and invalidate it on a Deny.
- **The panel's cancel and the user's cancel can be told apart.** The panel
  gives `-9` (app cancel); the dialog's own Cancel gives `-2` (user cancel).
  The audit can record "denied in JitPass" and "cancelled on the Touch ID"
  as different facts.
- **Clicks reach a non-activating panel while the dialog is up.** macOS did
  not block the click. The dialog (owner `coreautha`, layer 1000) is not
  modal to other windows.
- **Focus stays on the dialog.** An `NSPanel` with `.nonactivatingPanel`,
  `becomesKeyOnlyIfNeeded`, level `.statusBar`, in an app with the
  `.accessory` activation policy (as JitPass is), was never frontmost.
- **A stuck or absent app never delays a prompt beyond the cap.** No panel
  gives 14 ms; a silent panel gives 250 ms plus about 14 ms.

## A key from the keychain (added 2026-09-29, after test build 0.0.10)

The first live test of the real service failed check 1: the panel's Deny
reached the service, the request was refused and recorded as "denied in
JitPass", and the dialog stayed on screen until it was answered by hand
(15 s after the Deny in the measured run, lid closed, password dialog).

The runs above never saw this because their enclave key was made in-process
with the `LAContext` on it. The vault's key comes from the keychain
(`SecItemCopyMatching` with `kSecUseAuthenticationContext`), and such a key
carries the context's credential, not the context. When a decrypt needs the
human, Security prompts on a context of its own made from that credential,
and invalidating ours does not reach it.

`credref/exp.m` reproduces it with an ephemeral key that is handed only the
context's credential reference, and measures the fix: evaluate the key's own
access control on our context first, then decrypt.

| Run | Result |
| --- | --- |
| Control: the original spike, lid closed (password dialog), enclave | dialog gone 47 ms after the deny |
| Control: the same, keychain `evaluatePolicy` | dialog gone 38 ms after the deny |
| Credential reference only, decrypt directly, invalidate at 1.5 s | dialog stayed 10 s, until Cancel was pressed (`-2`) |
| Same key, access control evaluated first, invalidate at 1.5 s | evaluation returned `-9` in 3 ms, dialog gone in 55 ms |
| Same key, access control evaluated first, approved | decrypt returned in 6 ms, no second dialog |

- The password dialog is withdrawn like the Touch ID one. The lid being
  closed was not the cause.
- The operation to evaluate is key exchange
  (`LAAccessControlOperationUseKeyKeyExchange`). `UseKeyDecrypt` answers
  `-1009` "Operation is not allowed" at once, with no dialog, on this key's
  access control. An access control made with
  `SecAccessControlCreateWithFlags` and never given to a key answers `-1009`
  too: evaluate the key's own, from `SecKeyCopyAttributes`.
- `secureenclave`'s withdrawable open does this (`seAuthorize`). The plain
  open is unchanged.

To run it: `clang -fobjc-arc -framework Foundation -framework Security
-framework LocalAuthentication credref/exp.m -o exp`, then
`./exp credref direct cancel`, `./exp credref evalfirst cancel` and
`./exp credref evalfirst approve`. It uses two private names
(`externalizedContext`, `u_CredRef`) to build the key, which is why it is an
experiment and not a test.

## Not covered

- The real JitPass panel (warm) and the real service (the signed helper
  under launchd). The timings above come from standalone binaries.
- A cancel racing an approval in the same instant. `arm` and `cancel_prompt`
  handle a cancel that arrives before the prompt, but the approve-and-deny
  race was not driven.
- The keychain path's dialog timing was measured once (A2, 121 ms); the
  enclave path's ten times.
- A Mac with no Touch ID sensor. (Password entry with the lid closed is
  covered by the section above.)

## Notes for building it

- The window watcher must ignore windows owned by "Window Server": the
  first run latched onto a short-lived one of those on the keychain path.
  The dialog itself belonged to `coreautha` on every run.
- A unix socket path is capped at 104 bytes on macOS, so a socket under a
  deep scratch directory fails with "bind: invalid argument". jit's own
  socket path is short, so this only affects test harnesses.
