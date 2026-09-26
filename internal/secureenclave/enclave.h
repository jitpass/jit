#ifndef SECUREENCLAVE_ENCLAVE_H
#define SECUREENCLAVE_ENCLAVE_H

// The whole C surface of internal/secureenclave: one P-256 key in the Secure
// Enclave, found by (tag, access group) in the data-protection keychain, and
// the two operations on it. Everything returns an SEResult; status carries
// the OSStatus (or CFError code) so Go can classify without parsing text.

typedef struct {
    int success;
    int status;
    char *error_message;
} SEResult;

// se_present reports whether the key exists, WITHOUT using it, so it never
// prompts. 1 present, 0 absent (errSecItemNotFound); any other outcome is -1
// with *status set (errSecMissingEntitlement when this process cannot reach
// the access group at all).
int se_present(const char *tag, const char *group, int *status);

// se_create makes a new permanent enclave key. presence=1 adds
// kSecAccessControlUserPresence (Touch ID or the login password on every
// private-key use; the vault key); presence=0 is PrivateKeyUsage only (a key
// that never asks). after_first_unlock=1 uses
// kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, which a key that must
// work while the screen is locked needs (spike S4); 0 uses
// WhenUnlockedThisDeviceOnly.
SEResult se_create(const char *tag, const char *group, int presence, int after_first_unlock);

// se_delete removes the key. errSecItemNotFound is success.
SEResult se_delete(const char *tag, const char *group);

// se_seal encrypts to the key's PUBLIC half (ECIES, cofactor, variable IV,
// X9.63 SHA-256, AES-GCM). It never touches the private key, so it never
// prompts, even for a presence key (spike S1b). *out is malloc'd.
SEResult se_seal(const char *tag, const char *group, const unsigned char *pt, int pt_len,
                 unsigned char **out, int *out_len);

// se_open decrypts with the private key. For a presence key this is where
// the dialog appears, reading "<app> is trying to <reason>." *out is
// malloc'd.
SEResult se_open(const char *tag, const char *group, const unsigned char *ct, int ct_len,
                 const char *reason, unsigned char **out, int *out_len);

// se_list_tags returns the tag of every enclave key in group whose tag
// starts with prefix, from attributes only (never uses a key, never
// prompts). *tags is a malloc'd array of *count malloc'd strings.
SEResult se_list_tags(const char *group, const char *prefix, char ***tags, int *count);

// se_entitlements reads this process's OWN code-signing entitlements
// (SecTaskCreateFromSelf): *has_group is 1 when keychain-access-groups
// names group, and *app_id is the application identifier (malloc'd, NULL
// when there is none). It is no keychain query: it never prompts, and it
// answers the same whether the Mac is locked or not.
SEResult se_entitlements(const char *group, int *has_group, char **app_id);

#endif
