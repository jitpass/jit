// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <stdlib.h>
#include <string.h>
#include "sem.h"

static char *cerr(NSString *what, CFErrorRef e) {
    NSString *s = e ? [NSString stringWithFormat:@"%@: %@", what, (__bridge NSError *)e] : what;
    if (e) CFRelease(e);
    return strdup(s.UTF8String);
}

#define kAlg kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM

void *sem_new_key(int presence, char **err) {
    CFErrorRef e = NULL;
    SecAccessControlCreateFlags flags = kSecAccessControlPrivateKeyUsage;
    if (presence) flags |= kSecAccessControlUserPresence;
    SecAccessControlRef ac = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &e);
    if (!ac) { *err = cerr(@"access control", e); return NULL; }
    NSDictionary *attrs = @{
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
        (id)kSecAttrKeySizeInBits: @256,
        (id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave,
        (id)kSecPrivateKeyAttrs: @{ (id)kSecAttrIsPermanent: @NO, (id)kSecAttrAccessControl: (__bridge id)ac },
    };
    SecKeyRef k = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &e);
    CFRelease(ac);
    if (!k) { *err = cerr(@"SecKeyCreateRandomKey", e); return NULL; }
    return (void *)k;
}

void sem_free_key(void *key) { if (key) CFRelease((SecKeyRef)key); }

unsigned char *sem_seal(void *key, const unsigned char *pt, int ptlen, int *outlen, char **err) {
    SecKeyRef pub = SecKeyCopyPublicKey((SecKeyRef)key);
    if (!pub) { *err = strdup("no public key"); return NULL; }
    CFErrorRef e = NULL;
    NSData *in = [NSData dataWithBytes:pt length:ptlen];
    CFDataRef ct = SecKeyCreateEncryptedData(pub, kAlg, (__bridge CFDataRef)in, &e);
    CFRelease(pub);
    if (!ct) { *err = cerr(@"seal", e); return NULL; }
    *outlen = (int)CFDataGetLength(ct);
    unsigned char *out = malloc(*outlen);
    memcpy(out, CFDataGetBytePtr(ct), *outlen);
    CFRelease(ct);
    return out;
}

unsigned char *sem_open(void *key, const unsigned char *ct, int ctlen, const char *reason, int *outlen, char **err) {
    (void)reason; // S2 (interactive) carries it on an LAContext; S1 keys never prompt.
    CFErrorRef e = NULL;
    NSData *in = [NSData dataWithBytes:ct length:ctlen];
    CFDataRef pt = SecKeyCreateDecryptedData((SecKeyRef)key, kAlg, (__bridge CFDataRef)in, &e);
    if (!pt) { *err = cerr(@"open", e); return NULL; }
    *outlen = (int)CFDataGetLength(pt);
    unsigned char *out = malloc(*outlen);
    memcpy(out, CFDataGetBytePtr(pt), *outlen);
    CFRelease(pt);
    return out;
}

int sem_ecdh(void *key, char **err) {
    CFErrorRef e = NULL;
    NSDictionary *pa = @{ (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom, (id)kSecAttrKeySizeInBits: @256 };
    SecKeyRef peer = SecKeyCreateRandomKey((__bridge CFDictionaryRef)pa, &e);
    if (!peer) { *err = cerr(@"peer", e); return -1; }
    SecKeyRef peerPub = SecKeyCopyPublicKey(peer);
    CFDataRef shared = SecKeyCopyKeyExchangeResult((SecKeyRef)key, kSecKeyAlgorithmECDHKeyExchangeStandard, peerPub, (__bridge CFDictionaryRef)@{}, &e);
    CFRelease(peerPub); CFRelease(peer);
    if (!shared) { *err = cerr(@"ecdh", e); return -1; }
    int n = (int)CFDataGetLength(shared);
    CFRelease(shared);
    return n;
}
