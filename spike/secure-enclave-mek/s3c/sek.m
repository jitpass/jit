// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// The same Objective-C as s3a/sekey.m, compiled into a Go binary.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <stdio.h>
#include "sek.h"

static NSString *const kTag = @"com.jitpass.spike.kek";
static NSString *const kGroup = @"CZC6BH93GJ.com.jitpass.vault";
#define kAlg kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM

static int fail(NSString *what, CFErrorRef e, OSStatus st) {
    NSError *err = (__bridge NSError *)e;
    printf("FAIL %s: status=%d %s\n", what.UTF8String, (int)(e ? err.code : st),
           e ? err.localizedDescription.UTF8String : "");
    return 1;
}

static NSDictionary *query(void) {
    return @{
        (id)kSecClass: (id)kSecClassKey,
        (id)kSecAttrApplicationTag: [kTag dataUsingEncoding:NSUTF8StringEncoding],
        (id)kSecAttrAccessGroup: kGroup,
        (id)kSecUseDataProtectionKeychain: @YES,
        (id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave,
    };
}

static int doCreate(void) {
    CFErrorRef e = NULL;
    // No UserPresence here: S3a is about persistence, and a key that never
    // prompts lets it run unattended. The grant-key shape, in fact.
    SecAccessControlRef ac = SecAccessControlCreateWithFlags(NULL,
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, kSecAccessControlPrivateKeyUsage, &e);
    if (!ac) return fail(@"access control", e, 0);
    NSDictionary *attrs = @{
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
        (id)kSecAttrKeySizeInBits: @256,
        (id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave,
        (id)kSecUseDataProtectionKeychain: @YES,
        (id)kSecAttrAccessGroup: kGroup,
        (id)kSecPrivateKeyAttrs: @{
            (id)kSecAttrIsPermanent: @YES,
            (id)kSecAttrApplicationTag: [kTag dataUsingEncoding:NSUTF8StringEncoding],
            (id)kSecAttrAccessControl: (__bridge id)ac,
        },
    };
    SecKeyRef k = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &e);
    CFRelease(ac);
    if (!k) return fail(@"create persistent SE key", e, 0);
    CFRelease(k);
    printf("OK create: persistent SE key, tag %s, group %s\n", kTag.UTF8String, kGroup.UTF8String);
    return 0;
}

static int doFind(void) {
    NSMutableDictionary *q = [query() mutableCopy];
    q[(id)kSecReturnRef] = @YES;
    CFTypeRef ref = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &ref);
    if (st != errSecSuccess) return fail(@"find by tag", NULL, st);
    SecKeyRef k = (SecKeyRef)ref;
    // Seal a 32-byte MEK to its public half and open it with the enclave.
    uint8_t mek[32]; arc4random_buf(mek, sizeof mek);
    NSData *pt = [NSData dataWithBytes:mek length:sizeof mek];
    CFErrorRef e = NULL;
    SecKeyRef pub = SecKeyCopyPublicKey(k);
    CFDataRef ct = SecKeyCreateEncryptedData(pub, kAlg, (__bridge CFDataRef)pt, &e);
    CFRelease(pub);
    if (!ct) { CFRelease(k); return fail(@"seal", e, 0); }
    CFDataRef back = SecKeyCreateDecryptedData(k, kAlg, ct, &e);
    CFRelease(ct); CFRelease(k);
    if (!back) return fail(@"open", e, 0);
    BOOL same = [(__bridge NSData *)back isEqualToData:pt];
    CFRelease(back);
    printf("OK find: key found by tag from this process; MEK round trip identical: %s\n", same ? "true" : "false");
    return same ? 0 : 1;
}

static int doDelete(void) {
    OSStatus st = SecItemDelete((__bridge CFDictionaryRef)query());
    if (st != errSecSuccess && st != errSecItemNotFound) return fail(@"delete", NULL, st);
    printf("OK delete: status=%d (%s)\n", (int)st, st == errSecSuccess ? "removed" : "none present");
    return 0;
}

int sek_create(void) { @autoreleasepool { return doCreate(); } }
int sek_find(void) { @autoreleasepool { return doFind(); } }
int sek_delete(void) { @autoreleasepool { return doDelete(); } }
