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
// never called (or the item was deleted out-of-band). With quiet set, the
// read may not show any keychain dialog: one it would need fails it with
// errSecInteractionNotAllowed instead (kSecUseAuthenticationUIFail, and the
// process's keychain interaction off for the call).
KWResult kw_fetch_mek(const char *service, const char *account, unsigned char **key, int *key_len, int quiet);

// kw_mek_present checks whether the MEK item exists WITHOUT reading its
// bytes and without any dialog (kSecUseAuthenticationUIFail), and returns
// SecItemCopyMatching's raw OSStatus: errSecSuccess, errSecItemNotFound, or
// anything else, errSecInteractionNotAllowed included, which
// keychainwrap.presenceFromStatus reads as indeterminate. Lets `jit doctor`
// and `jit status` check on a non-interactive run.
int kw_mek_present(const char *service, const char *account);

// kw_item_delete is SecItemDelete over service/account, with no dialog. It
// returns the raw OSStatus; keychainwrap's deleteItem decides what it means.
int kw_item_delete(const char *service, const char *account);

// kw_item_delete_by_ref deletes every service/account item in the default
// (login) keychain through its reference (SecKeychainItemDelete), with no
// dialog: the fallback for an item SecItemDelete refuses as another
// executable's (errSecInvalidOwnerEdit, an older jit's item; keychain.m has
// why). Returns the lookup's status when it fails, errSecItemNotFound
// included, else the first failing delete's, else errSecSuccess.
int kw_item_delete_by_ref(const char *service, const char *account);

// kw_add_mek stores the GIVEN key bytes under service/account, which must
// not exist: the add half of keychainwrap's setMEK (the promote step of
// `jit vault rekey`, and a move back to the keychain), after deleteItem.
// Same plain-item, no-SecAccessControl posture as kw_ensure_mek.
KWResult kw_add_mek(const char *service, const char *account, const unsigned char *key, int key_len);

// kw_ui_scope_probe and kw_query_traits exist for keychainwrap's own tests,
// which cannot use cgo themselves. kw_ui_scope_probe sets the process's
// keychain interaction to start, reports it from inside kwWithoutUI and
// after it, then restores the original. kw_query_traits describes a query
// this file builds (0 presence, 1 the fallback's lookup, 2 the delete) as
// bits: 1 kSecUseAuthenticationUIFail, 2 searches only the default keychain,
// 4 returns data. Neither reads, writes or deletes an item.
int kw_ui_scope_probe(int start, int *during, int *after);
int kw_query_traits(int which);

// kw_set_user_interaction sets the process's keychain interaction for good.
// For the hardware tests only (keychainwrap.DisallowKeychainUITesting): with
// it off, no test can raise a keychain dialog.
void kw_set_user_interaction(int allowed);

// kw_list_accounts returns every account under service, from METADATA only
// (no kSecReturnData, so never the per-signature dialog). *accounts is a
// malloc'd array of *count malloc'd strings; the caller frees both.
KWResult kw_list_accounts(const char *service, char ***accounts, int *count);

// kw_biometry_available reports whether this Mac can satisfy a challenge with
// biometrics right now (Touch ID enrolled and usable) — 1 if so, 0 otherwise
// (no Touch ID hardware, none enrolled, or it's locked out). It only informs
// the audit log's "how were you asked" phrasing; it is never an authorization
// signal, and a challenge always still falls back to the device passcode.
int kw_biometry_available(void);

#endif
