// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

#ifndef SEM_H
#define SEM_H
#include <stddef.h>

// sem_* is the spike's whole C surface. An error comes back as a malloc'd
// string the caller frees; NULL means success.

// Mint a NON-persistent Secure Enclave P-256 key. presence=1 adds
// kSecAccessControlUserPresence (Touch ID or passcode on every private-key
// use); presence=0 is PrivateKeyUsage only, the grant-key shape. Returns an
// opaque handle (a retained SecKeyRef).
void *sem_new_key(int presence, char **err);
void sem_free_key(void *key);

// Seal: ECIES to the key's PUBLIC half. Never touches the private key, so it
// must never prompt, even for a presence key.
unsigned char *sem_seal(void *key, const unsigned char *pt, int ptlen, int *outlen, char **err);

// Open: ECIES decrypt with the private key. reason is the LAContext
// localizedReason; a presence key prompts here.
unsigned char *sem_open(void *key, const unsigned char *ct, int ctlen, const char *reason, int *outlen, char **err);

// Raw ECDH with the private key against a fresh software peer, the
// primitive a per-grant derived key would use.
int sem_ecdh(void *key, char **err);
#endif
