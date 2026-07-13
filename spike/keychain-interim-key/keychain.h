#ifndef KEYCHAIN_H
#define KEYCHAIN_H

typedef struct {
    int success;
    char *error_message;
} KCResult;

KCResult kc_generate_persistent_key(const char *tag);
KCResult kc_ecdh_with_stored_key(const char *tag, unsigned char **shared_secret, int *shared_secret_len);
KCResult kc_delete_key(const char *tag);
KCResult kc_key_exists(const char *tag, int *exists);

#endif
