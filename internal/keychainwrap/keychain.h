#ifndef KEYCHAIN_H
#define KEYCHAIN_H

typedef struct {
    int success;
    char *error_message;
} KWResult;

// kw_challenge triggers a standalone LocalAuthentication prompt (Touch ID,
// falling back to device passcode) independent of Keychain access control —
// see spike/keychain-interim-key/FINDINGS.md for why this, not a Keychain
// ACL, is the enforcement point in this interim implementation.
KWResult kw_challenge(const char *reason);

// kw_ensure_mek generates a random keySize-byte key on first call and
// stores it as a PLAIN (no SecAccessControl) keychain generic-password
// item under service/account if one doesn't already exist. Idempotent.
KWResult kw_ensure_mek(const char *service, const char *account, int keySize);

// kw_fetch_mek reads the stored MEK back out. Fails if kw_ensure_mek was
// never called (or the item was deleted out-of-band).
KWResult kw_fetch_mek(const char *service, const char *account, unsigned char **key, int *key_len);

// kw_delete_mek removes the stored item. Used by tests for cleanup; not
// expected to be part of normal CLI operation.
KWResult kw_delete_mek(const char *service, const char *account);

// kw_set_mek stores the GIVEN key bytes under service/account, replacing
// any existing item — the promote step of `jit vault rekey`, which must
// install the exact staged key every envelope was just rewrapped under
// (kw_ensure_mek can only generate a fresh random one). Same plain-item,
// no-SecAccessControl posture as kw_ensure_mek, same reasons.
KWResult kw_set_mek(const char *service, const char *account, const unsigned char *key, int key_len);

// kw_biometry_available reports whether this Mac can satisfy a challenge with
// biometrics right now (Touch ID enrolled and usable) — 1 if so, 0 otherwise
// (no Touch ID hardware, none enrolled, or it's locked out). It only informs
// the audit log's "how were you asked" phrasing; it is never an authorization
// signal, and a challenge always still falls back to the device passcode.
int kw_biometry_available(void);

#endif
