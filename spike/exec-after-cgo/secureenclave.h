#ifndef SECUREENCLAVE_H
#define SECUREENCLAVE_H

typedef struct {
    int success;
    char *error_message;
} SEResult;

SEResult se_check_biometry_available(void);
SEResult se_generate_key(const char *tag);
SEResult se_ecdh(const char *tag, unsigned char **shared_secret, int *shared_secret_len);
SEResult se_delete_key(const char *tag);
SEResult se_ephemeral_generate_and_ecdh(unsigned char **shared_secret, int *shared_secret_len);

#endif
