# Spike Findings: Plain Keychain-Persisted Key as an Interim MEK

**Question:** does a *plain* (non-Secure-Enclave) persistent keychain EC key — same shape as `spike/secure-enclave`, minus `kSecAttrTokenID: kSecAttrTokenIDSecureEnclave` — avoid the `-34018 errSecMissingEntitlement` that blocked Secure-Enclave-token persistence under ad-hoc signing?

**Environment:** macOS 26.5.1, Apple M5 Pro (arm64), Go 1.26.4, ad-hoc code signing only (no Developer ID — same constraint as `spike/secure-enclave`).

## Result: no — the entitlement wall is broader than Secure Enclave specifically

`kc_generate_persistent_key` (persistent EC key, `kSecAttrAccessControl` with `kSecAccessControlBiometryAny`, **no** `kSecAttrTokenID`) still failed:

```
OSStatus -34018 (errSecMissingEntitlement)
```

identical to the Secure-Enclave-token case. Two follow-up throwaway tests (not committed, results below) isolated exactly which attribute triggers it:

| Item type | `kSecAttrAccessControl` (biometry-gated) | Result |
|---|---|---|
| Plain `kSecClassGenericPassword`, `kSecAttrAccessibleWhenUnlocked` | No | **Succeeds** (`status: 0`) |
| `kSecClassGenericPassword` with `SecAccessControlCreateWithFlags(..., kSecAccessControlBiometryAny)` | Yes | **Fails**, same `-34018` |

**The entitlement macOS is missing isn't Secure-Enclave-specific — it's required for *any* `SecAccessControl`-gated keychain item** (biometric/passcode ACL enforcement), whether backed by a Secure Enclave key, a plain software key, or even a plain generic password. Only keychain items with **no** access-control gating persist successfully under ad-hoc signing.

## What this means for the vault's interim key-wrapping design

The original interim plan (plain keychain EC key + ECDH, biometry-gated, swap to Secure-Enclave-token later) doesn't work either — it hits the exact same wall. The only two things that actually function without a real Developer ID signing identity, verified above and against `spike/secure-enclave`'s own biometry-availability check:

1. **Plain keychain storage, no OS-enforced ACL.** A generic-password item persists fine, but macOS itself does not gate reading it behind Touch ID/passcode — any process running as this user can fetch it once it knows the service/account name (subject to the normal one-time "app wants to access a keychain item" consent prompt for cross-app access, not a per-use biometric challenge).
2. **`LAContext.evaluatePolicy` (`LocalAuthentication.framework`) works standalone**, independent of Keychain ACL — already confirmed in `spike/secure-enclave`'s `se_check_biometry_available`. Any app can trigger a real Touch ID/passcode prompt this way without special entitlements.

Combining them — MEK in a plain keychain item, gated by an **app-level** `LAContext` challenge before every use — gives a real Touch ID/passcode prompt on every `jit vault get`/`set`, but the enforcement lives in jit's own code path, not in the OS refusing to release the key. A determined attacker with existing code execution as this same local user could bypass the app-level check and read the keychain item directly. That is a materially weaker guarantee than true `SecAccessControl` or Secure-Enclave-token binding, where the OS itself won't release the key without a passing biometric check no matter what code is asking.

## Decision needed

This is one tier weaker than what was proposed as the "OS-keyring-bound" interim (which assumed ACL enforcement would at least work without Secure Enclave specifically). Taking this back to the user rather than silently building on it.

## How to reproduce

```bash
cd spike/keychain-interim-key
go build -o keychain-interim-key-spike .
codesign -s - --force keychain-interim-key-spike
./keychain-interim-key-spike generate   # fails with -34018, same as spike/secure-enclave's persistent path
```
