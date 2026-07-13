#import "keychain.h"
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <string.h>
#import <stdlib.h>

static char *dupNSString(NSString *s) {
    if (!s) return NULL;
    const char *utf8 = [s UTF8String];
    return strdup(utf8);
}

// Deliberately identical to spike/secure-enclave's se_generate_key, EXCEPT
// this omits kSecAttrTokenID: kSecAttrTokenIDSecureEnclave. The question
// this spike answers: does that alone avoid the -34018 errSecMissingEntitlement
// that blocked persistence for the real Secure-Enclave-token key under
// ad-hoc signing?
KCResult kc_generate_persistent_key(const char *tag) {
    KCResult r = {0, NULL};
    @autoreleasepool {
        NSData *tagData = [NSData dataWithBytes:tag length:strlen(tag)];

        CFErrorRef cfError = NULL;
        SecAccessControlRef access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAccessControlBiometryAny | kSecAccessControlPrivateKeyUsage,
            &cfError);

        if (!access) {
            NSError *nsError = (__bridge_transfer NSError *)cfError;
            r.error_message = dupNSString([nsError localizedDescription]);
            return r;
        }

        NSDictionary *privateKeyAttrs = @{
            (id)kSecAttrIsPermanent: @YES,
            (id)kSecAttrApplicationTag: tagData,
            (id)kSecAttrAccessControl: (__bridge id)access,
        };

        // No kSecAttrTokenID here — plain software keychain key, not Secure
        // Enclave-backed. This is the whole point of this spike.
        NSDictionary *attributes = @{
            (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecAttrKeySizeInBits: @256,
            (id)kSecPrivateKeyAttrs: privateKeyAttrs,
        };

        CFErrorRef genError = NULL;
        SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes, &genError);

        CFRelease(access);

        if (!privateKey) {
            NSError *nsError = (__bridge_transfer NSError *)genError;
            r.error_message = dupNSString([NSString stringWithFormat:@"OSStatus/domain=%@ code=%ld: %@", nsError.domain, (long)nsError.code, [nsError localizedDescription]]);
            return r;
        }

        CFRelease(privateKey);
        r.success = 1;
    }
    return r;
}

KCResult kc_key_exists(const char *tag, int *exists) {
    KCResult r = {0, NULL};
    *exists = 0;
    @autoreleasepool {
        NSData *tagData = [NSData dataWithBytes:tag length:strlen(tag)];
        NSDictionary *query = @{
            (id)kSecClass: (id)kSecClassKey,
            (id)kSecAttrApplicationTag: tagData,
            (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecReturnRef: @YES,
        };
        CFTypeRef foundKey = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &foundKey);
        if (status == errSecSuccess && foundKey) {
            *exists = 1;
            CFRelease(foundKey);
        }
        r.success = 1;
    }
    return r;
}

// Looks the key up FRESH from keychain (simulating a brand new process
// invocation finding a key created by an earlier one) and performs ECDH —
// expected to trigger a Touch ID/passcode prompt because of the stored
// access control.
KCResult kc_ecdh_with_stored_key(const char *tag, unsigned char **shared_secret, int *shared_secret_len) {
    KCResult r = {0, NULL};
    @autoreleasepool {
        NSData *tagData = [NSData dataWithBytes:tag length:strlen(tag)];

        NSDictionary *query = @{
            (id)kSecClass: (id)kSecClassKey,
            (id)kSecAttrApplicationTag: tagData,
            (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecReturnRef: @YES,
        };

        CFTypeRef foundKey = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &foundKey);
        if (status != errSecSuccess || !foundKey) {
            r.error_message = dupNSString([NSString stringWithFormat:@"key lookup failed, OSStatus=%d", (int)status]);
            return r;
        }
        SecKeyRef privateKey = (SecKeyRef)foundKey;

        NSDictionary *peerAttrs = @{
            (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecAttrKeySizeInBits: @256,
        };
        CFErrorRef peerErr = NULL;
        SecKeyRef peerPrivate = SecKeyCreateRandomKey((__bridge CFDictionaryRef)peerAttrs, &peerErr);
        if (!peerPrivate) {
            NSError *nsError = (__bridge_transfer NSError *)peerErr;
            r.error_message = dupNSString([NSString stringWithFormat:@"peer key generation failed: %@", [nsError localizedDescription]]);
            CFRelease(privateKey);
            return r;
        }
        SecKeyRef peerPublic = SecKeyCopyPublicKey(peerPrivate);

        NSDictionary *params = @{ (id)kSecKeyKeyExchangeParameterRequestedSize: @32 };

        CFErrorRef exErr = NULL;
        CFDataRef shared = SecKeyCopyKeyExchangeResult(
            privateKey,
            kSecKeyAlgorithmECDHKeyExchangeStandard,
            peerPublic,
            (__bridge CFDictionaryRef)params,
            &exErr);

        CFRelease(peerPublic);
        CFRelease(peerPrivate);
        CFRelease(privateKey);

        if (!shared) {
            NSError *nsError = (__bridge_transfer NSError *)exErr;
            r.error_message = dupNSString([nsError localizedDescription]);
            return r;
        }

        NSData *sharedData = (__bridge_transfer NSData *)shared;
        *shared_secret_len = (int)sharedData.length;
        unsigned char *buf = malloc(*shared_secret_len);
        memcpy(buf, sharedData.bytes, *shared_secret_len);
        *shared_secret = buf;

        r.success = 1;
    }
    return r;
}

KCResult kc_delete_key(const char *tag) {
    KCResult r = {0, NULL};
    @autoreleasepool {
        NSData *tagData = [NSData dataWithBytes:tag length:strlen(tag)];
        NSDictionary *query = @{
            (id)kSecClass: (id)kSecClassKey,
            (id)kSecAttrApplicationTag: tagData,
            (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
        };
        OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
        if (status != errSecSuccess && status != errSecItemNotFound) {
            r.error_message = dupNSString([NSString stringWithFormat:@"delete failed, OSStatus=%d", (int)status]);
            return r;
        }
        r.success = 1;
    }
    return r;
}
