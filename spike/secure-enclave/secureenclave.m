#import "secureenclave.h"
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

SEResult se_check_biometry_available(void) {
    SEResult r = {0, NULL};
    @autoreleasepool {
        LAContext *ctx = [[LAContext alloc] init];
        NSError *error = nil;
        BOOL canEvaluate = [ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
        r.success = canEvaluate ? 1 : 0;
        if (!canEvaluate && error) {
            r.error_message = dupNSString([error localizedDescription]);
        }
    }
    return r;
}

SEResult se_generate_key(const char *tag) {
    SEResult r = {0, NULL};
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

        NSDictionary *attributes = @{
            (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecAttrKeySizeInBits: @256,
            (id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave,
            (id)kSecPrivateKeyAttrs: privateKeyAttrs,
        };

        CFErrorRef genError = NULL;
        SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes, &genError);

        CFRelease(access);

        if (!privateKey) {
            NSError *nsError = (__bridge_transfer NSError *)genError;
            r.error_message = dupNSString([nsError localizedDescription]);
            return r;
        }

        CFRelease(privateKey);
        r.success = 1;
    }
    return r;
}

SEResult se_ecdh(const char *tag, unsigned char **shared_secret, int *shared_secret_len) {
    SEResult r = {0, NULL};
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
        // This is the call expected to trigger the Touch ID / passcode prompt,
        // because the stored private key carries kSecAccessControlBiometryAny.
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

// se_ephemeral_generate_and_ecdh isolates the crypto/biometric question from the
// keychain-persistence question: generates a Secure-Enclave-backed key WITHOUT
// kSecAttrIsPermanent (so no SecItemAdd, no keychain-write entitlement needed),
// then immediately performs ECDH with the in-memory SecKeyRef. If this triggers
// Touch ID and returns a shared secret, the core mechanism works — persistence
// is a separate, orthogonal signing concern (see the -34018 finding).
SEResult se_ephemeral_generate_and_ecdh(unsigned char **shared_secret, int *shared_secret_len) {
    SEResult r = {0, NULL};
    @autoreleasepool {
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
            (id)kSecAttrIsPermanent: @NO,
            (id)kSecAttrAccessControl: (__bridge id)access,
        };

        NSDictionary *attributes = @{
            (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecAttrKeySizeInBits: @256,
            (id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave,
            (id)kSecPrivateKeyAttrs: privateKeyAttrs,
        };

        CFErrorRef genError = NULL;
        SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes, &genError);
        CFRelease(access);

        if (!privateKey) {
            NSError *nsError = (__bridge_transfer NSError *)genError;
            r.error_message = dupNSString([NSString stringWithFormat:@"ephemeral key generation failed: %@", [nsError localizedDescription]]);
            return r;
        }

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
        // Expected to trigger the Touch ID / passcode prompt.
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

SEResult se_delete_key(const char *tag) {
    SEResult r = {0, NULL};
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
