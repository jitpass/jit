#ifndef KEYCHAIN_H
#define KEYCHAIN_H

typedef struct {
    int success;
    char *error_message;
    // status is the failing call's OSStatus where the caller decides on it
    // (kw_fetch_mek and kw_fetch_quiet_no_switch set it); 0 otherwise.
    int status;
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

// kw_fetch_quiet_no_switch is kw_fetch_mek's quiet read without the
// process-wide interaction switch, for the service's grant and job keys: the
// query alone carries kSecUseAuthenticationUIFail, and a locked default
// keychain (or one whose lock state can't be read) is not read at all and
// answers errSecInteractionNotAllowed (keychain.m has why).
KWResult kw_fetch_quiet_no_switch(const char *service, const char *account, unsigned char **key, int *key_len);

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

// kw_item_delete_by_ref_no_switch is kw_item_delete_by_ref WITHOUT the
// process-wide interaction switch around the lookup and the deletes: the
// service's grant and job key deletes (GrantKeys.Delete), where flipping
// that switch would reach every other request in flight. The lookup still
// carries kSecUseAuthenticationUIFail; the delete needs no UI on these
// items (S3g rows 8 and 9, the locked-keychain test; keychain.m has the
// measurements). Its caller checks the default keychain is unlocked first
// (kw_default_keychain_lock_state).
int kw_item_delete_by_ref_no_switch(const char *service, const char *account);

// kw_default_keychain_lock_state reads the default (login) keychain's lock
// state with SecKeychainGetStatus, which shows no UI: 1 unlocked, 0 locked,
// else the failing OSStatus (SecKeychainCopyDefault's or
// SecKeychainGetStatus's; never 0 or 1). The service asks it before its
// reference delete (keychainwrap's deleteItem, serviceRefFallback), which
// runs with the process's interaction as the service has it: on a locked
// keychain the delete is not attempted at all.
int kw_default_keychain_lock_state(void);

// kw_add_mek stores the GIVEN key bytes under service/account, which must
// not exist: the add half of keychainwrap's setMEK (the promote step of
// `jit vault rekey`, and a move back to the keychain), after deleteItem.
// Same plain-item, no-SecAccessControl posture as kw_ensure_mek.
KWResult kw_add_mek(const char *service, const char *account, const unsigned char *key, int key_len);

// The queries keychain.m builds, each by its number through kwQuery, the
// one builder: the registry keychainwrap's traits test walks from 0 to
// KW_Q_COUNT, so a query added here is checked without anyone remembering
// to list it (TestEveryQueryIsChecked), and no query is built anywhere else
// (TestEveryQueryGoesThroughTheRegistry).
enum {
    KW_Q_PRESENCE = 0,     // status, doctor, a fetch's absence check: metadata, no dialog
    KW_Q_PRESENCE_DEFAULT, // after a reference delete: the default keychain only
    KW_Q_REF,              // the reference delete's lookup
    KW_Q_DELETE,           // SecItemDelete
    KW_Q_FETCH_QUIET,      // the quiet read (CountOpens, MatchesMEK, InstallMEK): no dialog
    KW_Q_FETCH,            // the read behind jit's Touch ID check; may prompt (TestEveryQueryIsChecked lists its callers)
    KW_Q_EXISTS,           // kw_ensure_mek's check before it adds
    KW_Q_LIST,             // grant key ids, from metadata
    KW_Q_COUNT
};

// kw_mek_present_default is kw_mek_present over the default (login)
// keychain only, the one kw_item_delete_by_ref deletes in: deleteItem's
// check after a reference delete, which must not see an item of the same
// name in some other keychain on the search list as "still there".
int kw_mek_present_default(const char *service, const char *account);

// For keychainwrap's own tests, which cannot use cgo themselves; none reads,
// writes or deletes a production item.
//
// kw_query_count, kw_query_name and kw_query_traits describe the registry:
// traits are bits, 1 kSecUseAuthenticationUIFail, 2 searches only the
// default keychain, 4 returns data, 8 returns attributes, 16 returns refs.
int kw_query_count(void);
const char *kw_query_name(int which);
int kw_query_traits(int which);

// kw_ui_scope_probe sets the process's keychain interaction to start,
// reports it from inside kwWithoutUI (with a nested use inside) and after
// it, then restores the original. kw_ui_overlap_probe runs one kwWithoutUI
// that sleeps usec inside and returns 1 if interaction stayed off the whole
// time: many at once are the race test of its save and restore.
// kw_get_user_interaction reads the process's setting.
int kw_ui_scope_probe(int start, int *during, int *after);
int kw_ui_overlap_probe(int usec);
int kw_get_user_interaction(void);

// kw_set_user_interaction sets the process's keychain interaction for good.
// For the hardware tests only (keychainwrap.DisallowKeychainUITesting): with
// it off, no test can raise a keychain dialog.
void kw_set_user_interaction(int allowed);

// kw_add_in_keychain and kw_probe_in_keychain work on a keychain FILE the
// hardware test creates and locks itself (TEST-ONLY names only): the add
// makes an item in it from this binary; the probe runs one registry query
// (KW_Q_PRESENCE, KW_Q_FETCH_QUIET or KW_Q_DELETE), or the delete by
// reference (KW_Q_REF), against that keychain alone, with the process's
// interaction switched off around it only when without_ui is set, and
// returns its status.
//
// KW_PROBE_LOCK_STATE is not a registry query: with it, the probe returns
// that keychain's lock state as kw_default_keychain_lock_state reads the
// default one's (the same helper).
#define KW_PROBE_LOCK_STATE 1000
int kw_add_in_keychain(const char *path, const char *service, const char *account);
int kw_probe_in_keychain(const char *path, const char *service, const char *account, int which, int without_ui);

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
