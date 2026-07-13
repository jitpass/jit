# Spike Findings: LaunchAgent + Touch ID Compatibility

**Question:** can a process started by `launchd` as a per-user LaunchAgent (not from an interactive terminal, no attached tool call) successfully trigger a real `LAContext` Touch ID/passcode dialog? Earlier in this project, processes launched via an automated tool call (no window-server session) could not — this spike checks whether a proper LaunchAgent has the same limitation, since the entire "persistent jit-agent, like 1Password's desktop app" design depends on the answer.

**Environment:** macOS 26.5.1, Apple M5 Pro (arm64), Go 1.26.4, ad-hoc code signing.

## Result: confirmed working — LaunchAgents CAN show Touch ID dialogs

A minimal binary (`la_challenge`, calling `LAContext.evaluatePolicy(LAPolicyDeviceOwnerAuthentication)`) was registered as a temporary LaunchAgent (`~/Library/LaunchAgents/com.jitpass.spike.touchid.plist`, `RunAtLoad: true`) and loaded with `launchctl load`. It successfully displayed a real dialog, approved by the user, and logged:

```
[...] launchagent-touchid-spike started, pid=57523
[...] RESULT: SUCCESS — challenge approved, LaunchAgent CAN show Touch ID/passcode dialogs
```

(Results logged to a file, not stdout — a launchd-managed agent has no attached terminal to print to.)

## Implication

Per-user LaunchAgents run WITH the user's GUI/window-server session — unlike LaunchDaemons (root, no GUI access) or a process spawned by a headless automated tool call. This is exactly why other tools (1Password, Docker Desktop, Dropbox) use LaunchAgents specifically to get a persistent, GUI-session-attached background process. Confirms the persistent jit-agent design (launchd-managed process, internal lock/unlock state, Touch ID challenge on unlock) is buildable as specified — no fallback design needed.

## Cleanup

The plist and log file were both removed immediately after this result was captured; `launchctl unload` ran before deletion. No trace of this spike persists on the machine.

## How to reproduce

```bash
cd spike/launchagent-touchid
go build -o launchagent-touchid-spike .
codesign -s - --force launchagent-touchid-spike

PLIST="$HOME/Library/LaunchAgents/com.jitpass.spike.touchid.plist"
# write a plist pointing ProgramArguments at this binary's absolute path, RunAtLoad: true
launchctl load "$PLIST"
# approve the Touch ID/passcode prompt when it appears
cat /tmp/jit-launchagent-touchid-spike.log

launchctl unload "$PLIST"
rm -f "$PLIST" /tmp/jit-launchagent-touchid-spike.log
```
