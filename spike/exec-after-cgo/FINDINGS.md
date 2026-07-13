# Spike Findings: syscall.Exec Reliability After CGo/LocalAuthentication Use

**Question:** is `syscall.Exec` (Tier 1 process-replacement injection, RFC.md Pillar III) reliable immediately after this same process has used CGo + Objective-C runtime + LocalAuthentication/Security framework calls? CGo/ObjC runtimes can spawn background threads (dispatch queues, XPC connections) that have a known history of causing flaky `execve` behavior in some configurations elsewhere in the ecosystem — Tier 1's entire design depends on this being rock solid.

**Environment:** macOS 26.5.1, arm64, Go 1.26.4.

## Result: PASS, no flakiness observed

**Automated pass (15 iterations, no user interaction):** each iteration called `se_check_biometry_available()` (touches `LocalAuthentication.framework`, creates an `LAContext`, exercises the same CGo/ObjC boundary without an interactive prompt) immediately followed by `syscall.Exec` replacing the process with `/bin/echo`. All 15/15 iterations succeeded — the exec'd command's output appeared correctly every time, no hangs, no crashes.

**Real-world pass (the actual production sequence, 1 iteration, Touch ID approved):** ephemeral Secure Enclave key generation → Touch-ID-gated ECDH (the full flow from the `secure-enclave` spike) → immediate `syscall.Exec`. Succeeded cleanly: ECDH returned a 32-byte shared secret, and the exec'd process's output confirmed the process image was correctly replaced right after.

## Implication

No evidence of the flakiness pattern this spike was checking for. Tier 1's core mechanism — decrypt via Touch ID, then `execve` over the current process — is safe to build on as specified in RFC.md. Not exhaustively stress-tested (e.g., under memory pressure, or with a much larger number of iterations), but a real 15x automated pass plus one full real-world pass is enough signal to proceed with implementation rather than block on more spiking here.

## How to reproduce

```bash
cd spike/exec-after-cgo
go build -o exec-after-cgo-spike .
codesign -s - --force exec-after-cgo-spike

# Automated, no Touch ID needed:
for i in $(seq 1 15); do ./exec-after-cgo-spike -phase check -iteration "$i"; done

# Real-world flow, needs one Touch ID approval:
./exec-after-cgo-spike -phase ecdh -iteration real
```
