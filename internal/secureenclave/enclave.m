#import "enclave.h"
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <stdlib.h>
#import <string.h>

#define kSEAlgorithm kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM

static char *dupNSString(NSString *s) {
    if (!s) return NULL;
    return strdup([s UTF8String]);
}

static SEResult fail(NSString *what, OSStatus status) {
    SEResult r = {0, (int)status, NULL};
    r.error_message = dupNSString([NSString stringWithFormat:@"%@ (OSStatus=%d)", what, (int)status]);
    return r;
}

// failCF takes ownership of e. A CFError's code is an OSStatus for the
// Security domain and an LAError for LocalAuthentication (LAErrorUserCancel
// is -2); both travel as status and Go classifies them.
static SEResult failCF(NSString *what, CFErrorRef e) {
    NSError *err = (__bridge_transfer NSError *)e;
    SEResult r = {0, err ? (int)err.code : 0, NULL};
    r.error_message = dupNSString([NSString stringWithFormat:@"%@: %@", what,
                                   err ? err.localizedDescription : @"unknown error"]);
    return r;
}

static NSMutableDictionary *keyQuery(const char *tag, const char *group) {
    return [@{
        (id)kSecClass: (id)kSecClassKey,
        (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPrivate,
        (id)kSecAttrApplicationTag: [NSData dataWithBytes:tag length:strlen(tag)],
        (id)kSecAttrAccessGroup: [NSString stringWithUTF8String:group],
        (id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave,
        (id)kSecUseDataProtectionKeychain: @YES,
    } mutableCopy];
}

// copyKey returns the private key's reference. Fetching a reference never
// uses the key, so it never prompts; ctx, when given, is carried to the
// operation that does.
static SecKeyRef copyKey(const char *tag, const char *group, LAContext *ctx, OSStatus *status) {
    NSMutableDictionary *q = keyQuery(tag, group);
    q[(id)kSecReturnRef] = @YES;
    if (ctx) q[(id)kSecUseAuthenticationContext] = ctx;
    CFTypeRef ref = NULL;
    *status = SecItemCopyMatching((__bridge CFDictionaryRef)q, &ref);
    return *status == errSecSuccess ? (SecKeyRef)ref : NULL;
}

int se_present(const char *tag, const char *group, int *status) {
    @autoreleasepool {
        OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)keyQuery(tag, group), NULL);
        *status = (int)st;
        if (st == errSecSuccess) return 1;
        if (st == errSecItemNotFound) return 0;
        return -1;
    }
}

SEResult se_create(const char *tag, const char *group, int presence, int after_first_unlock) {
    @autoreleasepool {
        CFErrorRef e = NULL;
        SecAccessControlCreateFlags flags = kSecAccessControlPrivateKeyUsage;
        if (presence) flags |= kSecAccessControlUserPresence;
        CFStringRef accessible = after_first_unlock
            ? kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            : kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
        SecAccessControlRef ac = SecAccessControlCreateWithFlags(kCFAllocatorDefault, accessible, flags, &e);
        if (!ac) return failCF(@"building the key's access control", e);
        NSDictionary *attrs = @{
            (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecAttrKeySizeInBits: @256,
            (id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave,
            (id)kSecUseDataProtectionKeychain: @YES,
            (id)kSecAttrAccessGroup: [NSString stringWithUTF8String:group],
            (id)kSecPrivateKeyAttrs: @{
                (id)kSecAttrIsPermanent: @YES,
                (id)kSecAttrApplicationTag: [NSData dataWithBytes:tag length:strlen(tag)],
                (id)kSecAttrAccessControl: (__bridge id)ac,
            },
        };
        SecKeyRef k = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &e);
        CFRelease(ac);
        if (!k) return failCF(@"creating the Secure Enclave key", e);
        CFRelease(k);
        SEResult r = {1, 0, NULL};
        return r;
    }
}

SEResult se_delete(const char *tag, const char *group) {
    @autoreleasepool {
        OSStatus st = SecItemDelete((__bridge CFDictionaryRef)keyQuery(tag, group));
        if (st != errSecSuccess && st != errSecItemNotFound) {
            return fail(@"deleting the Secure Enclave key", st);
        }
        SEResult r = {1, 0, NULL};
        return r;
    }
}

// copyOut returns 0 when it could not allocate; the caller reports it.
static int copyOut(CFDataRef d, unsigned char **out, int *out_len) {
    CFIndex n = CFDataGetLength(d);
    if (n <= 0) return 0;
    *out = malloc((size_t)n);
    if (!*out) return 0;
    memcpy(*out, CFDataGetBytePtr(d), (size_t)n);
    *out_len = (int)n;
    return 1;
}

SEResult se_seal(const char *tag, const char *group, const unsigned char *pt, int pt_len,
                 unsigned char **out, int *out_len) {
    @autoreleasepool {
        OSStatus st = 0;
        SecKeyRef k = copyKey(tag, group, nil, &st);
        if (!k) return fail(@"finding the Secure Enclave key", st);
        SecKeyRef pub = SecKeyCopyPublicKey(k);
        CFRelease(k);
        if (!pub) return fail(@"reading the Secure Enclave key's public half", errSecInternalComponent);
        CFErrorRef e = NULL;
        NSData *in = [NSData dataWithBytesNoCopy:(void *)pt length:pt_len freeWhenDone:NO];
        CFDataRef ct = SecKeyCreateEncryptedData(pub, kSEAlgorithm, (__bridge CFDataRef)in, &e);
        CFRelease(pub);
        if (!ct) return failCF(@"sealing to the Secure Enclave key", e);
        int ok = copyOut(ct, out, out_len);
        CFRelease(ct);
        if (!ok) return fail(@"copying the sealed key", errSecAllocate);
        SEResult r = {1, 0, NULL};
        return r;
    }
}

SEResult se_open(const char *tag, const char *group, const unsigned char *ct, int ct_len,
                 const char *reason, unsigned char **out, int *out_len, int *decrypting) {
    @autoreleasepool {
        *decrypting = 0;
        LAContext *ctx = [[LAContext alloc] init];
        ctx.localizedReason = [NSString stringWithUTF8String:reason];
        OSStatus st = 0;
        SecKeyRef k = copyKey(tag, group, ctx, &st);
        if (!k) return fail(@"finding the Secure Enclave key", st);
        CFErrorRef e = NULL;
        NSData *in = [NSData dataWithBytesNoCopy:(void *)ct length:ct_len freeWhenDone:NO];
        CFDataRef pt = SecKeyCreateDecryptedData(k, kSEAlgorithm, (__bridge CFDataRef)in, &e);
        CFRelease(k);
        if (!pt) {
            *decrypting = 1;
            return failCF(@"opening with the Secure Enclave key", e);
        }
        int ok = copyOut(pt, out, out_len);
        // CoreFoundation's own copy is released, not zeroed: a CFDataRef is
        // immutable and writing through CFDataGetBytePtr is not a promise
        // the framework makes. The malloc'd copy handed to Go is wiped there.
        CFRelease(pt);
        if (!ok) return fail(@"copying the opened key", errSecAllocate);
        SEResult r = {1, 0, NULL};
        return r;
    }
}

SEResult se_list_tags(const char *group, const char *prefix, char ***tags, int *count) {
    @autoreleasepool {
        *tags = NULL;
        *count = 0;
        NSDictionary *q = @{
            (id)kSecClass: (id)kSecClassKey,
            (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPrivate,
            (id)kSecAttrAccessGroup: [NSString stringWithUTF8String:group],
            (id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave,
            (id)kSecUseDataProtectionKeychain: @YES,
            (id)kSecReturnAttributes: @YES,
            (id)kSecMatchLimit: (id)kSecMatchLimitAll,
        };
        CFTypeRef result = NULL;
        OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &result);
        if (st == errSecItemNotFound) {
            SEResult r = {1, 0, NULL};
            return r;
        }
        if (st != errSecSuccess || !result) return fail(@"listing Secure Enclave keys", st);
        NSArray *items = (__bridge_transfer NSArray *)result;
        NSString *want = [NSString stringWithUTF8String:prefix];
        char **out = calloc(items.count ? items.count : 1, sizeof(char *));
        if (!out) return fail(@"listing Secure Enclave keys", errSecAllocate);
        int n = 0;
        for (NSDictionary *item in items) {
            NSData *tag = item[(id)kSecAttrApplicationTag];
            if (![tag isKindOfClass:[NSData class]]) continue;
            NSString *s = [[NSString alloc] initWithData:tag encoding:NSUTF8StringEncoding];
            if (s && [s hasPrefix:want]) out[n++] = dupNSString(s);
        }
        *tags = out;
        *count = n;
        SEResult r = {1, 0, NULL};
        return r;
    }
}

SEResult se_entitlements(const char *group, int *has_group, char **app_id) {
    @autoreleasepool {
        *has_group = 0;
        *app_id = NULL;
        SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
        if (!task) return fail(@"reading this process's code signature", errSecInternalComponent);
        CFErrorRef e = NULL;
        id groups = CFBridgingRelease(SecTaskCopyValueForEntitlement(task, CFSTR("keychain-access-groups"), &e));
        if (e) {
            CFRelease(task);
            return failCF(@"reading the keychain-access-groups entitlement", e);
        }
        id appID = CFBridgingRelease(SecTaskCopyValueForEntitlement(task, CFSTR("com.apple.application-identifier"), &e));
        CFRelease(task);
        if (e) return failCF(@"reading the application-identifier entitlement", e);
        NSString *want = [NSString stringWithUTF8String:group];
        if ([groups isKindOfClass:[NSArray class]]) {
            for (id g in (NSArray *)groups) {
                if ([g isKindOfClass:[NSString class]] && [g isEqualToString:want]) *has_group = 1;
            }
        }
        if ([appID isKindOfClass:[NSString class]]) *app_id = dupNSString(appID);
        SEResult r = {1, 0, NULL};
        return r;
    }
}
