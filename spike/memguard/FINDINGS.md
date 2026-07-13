# Spike Findings: memguard Secure-Memory Smoke Test

**Question:** does `github.com/awnumar/memguard` build and run cleanly on this macOS/arm64 setup before it gets threaded through every place a decrypted secret touches memory (Pillar II)?

**Environment:** macOS 26.5.1, arm64, Go 1.26.4, memguard v0.23.0.

## Result: PASS, all four checks

1. `memguard.NewBufferFromBytes` — locked buffer allocation succeeded (mlock works fine on this hardware, no ulimit issues).
2. `Seal()` → `Open()` — round trip through an encrypted enclave preserved the secret correctly.
3. `Destroy()` — completed cleanly, buffer correctly reports not-alive afterward.
4. `CatchInterrupt()` — registers without error.

## Real finding along the way (not a bug): memguard wipes its input argument

First test run failed an equality check — turned out to be a test-harness mistake, not a memguard problem. `NewBufferFromBytes(secret)` **zeroes out the `secret` slice you pass in** after copying it into the locked buffer. This is memguard behaving correctly and defensively: it doesn't want a plaintext copy of the secret surviving in ordinary (non-locked, swappable) memory after ingestion into the locked buffer.

**Implication for the real vault code:** any call site doing `memguard.NewBufferFromBytes(decryptedDEK)` needs to expect `decryptedDEK` to be zeroed as a side effect. Don't read from that slice afterward expecting the original value — read from the returned `*memguard.LockedBuffer` instead. Worth a one-line comment at each call site in the real implementation, since this is exactly the kind of "why does this variable look zeroed" surprise that wastes debugging time if undocumented.

## How to reproduce

```bash
cd spike/memguard
go build -o memguard-spike .
./memguard-spike
```
