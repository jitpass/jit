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

KWResult kw_challenge(const char *reason) {
    KWResult r = {0, NULL};
    @autoreleasepool {
        NSString *reasonStr = [NSString stringWithUTF8String:reason];
        LAContext *ctx = [[LAContext alloc] init];

        __block int done = 0;
        __block BOOL approved = NO;
        __block NSString *errMsg = nil;

        [ctx evaluatePolicy:LAPolicyDeviceOwnerAuthentication
             localizedReason:reasonStr
                       reply:^(BOOL success, NSError *error) {
            approved = success;
            if (error) {
                errMsg = [error localizedDescription];
            }
            done = 1;
        }];

        // evaluatePolicy's reply runs on an arbitrary queue; block this
        // thread until it fires by pumping the run loop, since this is a
        // synchronous CGo call with no async story on the Go side.
        NSDate *timeout = [NSDate dateWithTimeIntervalSinceNow:120];
        while (!done && [timeout timeIntervalSinceNow] > 0) {
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
        }

        if (!done) {
            r.error_message = strdup("local authentication timed out waiting for a response");
            return r;
        }
        if (!approved) {
            r.error_message = dupNSString(errMsg ?: @"local authentication was not approved");
            return r;
        }
        r.success = 1;
    }
    return r;
}

int kw_biometry_available(void) {
    @autoreleasepool {
        LAContext *ctx = [[LAContext alloc] init];
        // canEvaluatePolicy with the biometrics-only policy answers "could a
        // fingerprint satisfy a challenge right now" — false on a Mac with no
        // Touch ID, none enrolled, or biometry locked out after too many
        // failures. It performs no prompt. The passcode-inclusive policy jit
        // actually challenges with (kw_challenge) still works regardless; this
        // only sharpens the audit log's description of how the user was asked.
        BOOL ok = [ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:NULL];
        return ok ? 1 : 0;
    }
}

KWResult kw_ensure_mek(const char *service, const char *account, int keySize) {
    KWResult r = {0, NULL};
    @autoreleasepool {
        NSString *svc = [NSString stringWithUTF8String:service];
        NSString *acct = [NSString stringWithUTF8String:account];

        NSDictionary *query = @{
            (id)kSecClass: (id)kSecClassGenericPassword,
            (id)kSecAttrService: svc,
            (id)kSecAttrAccount: acct,
        };
        OSStatus existsStatus = SecItemCopyMatching((__bridge CFDictionaryRef)query, NULL);
        if (existsStatus == errSecSuccess) {
            r.success = 1; // already initialized — idempotent no-op
            return r;
        }
        if (existsStatus != errSecItemNotFound) {
            r.error_message = dupNSString([NSString stringWithFormat:@"checking for existing key failed, OSStatus=%d", (int)existsStatus]);
            return r;
        }

        NSMutableData *key = [NSMutableData dataWithLength:keySize];
        int status = SecRandomCopyBytes(kSecRandomDefault, keySize, key.mutableBytes);
        if (status != errSecSuccess) {
            r.error_message = strdup("generating random key material failed");
            return r;
        }

        // Deliberately NO kSecAttrAccessControl: see
        // spike/keychain-interim-key/FINDINGS.md — any ACL-gated item hits
        // -34018 without a real Developer ID signing identity. Local-auth
        // enforcement for this interim implementation lives in
        // kw_challenge (application-level), not here (OS-level).
        NSDictionary *addQuery = @{
            (id)kSecClass: (id)kSecClassGenericPassword,
            (id)kSecAttrService: svc,
            (id)kSecAttrAccount: acct,
            (id)kSecValueData: key,
            (id)kSecAttrAccessible: (id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        };
        OSStatus addStatus = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
        if (addStatus != errSecSuccess) {
            r.error_message = dupNSString([NSString stringWithFormat:@"storing key in keychain failed, OSStatus=%d", (int)addStatus]);
            return r;
        }
        r.success = 1;
    }
    return r;
}

KWResult kw_fetch_mek(const char *service, const char *account, unsigned char **key, int *key_len) {
    KWResult r = {0, NULL};
    @autoreleasepool {
        NSString *svc = [NSString stringWithUTF8String:service];
        NSString *acct = [NSString stringWithUTF8String:account];

        NSDictionary *query = @{
            (id)kSecClass: (id)kSecClassGenericPassword,
            (id)kSecAttrService: svc,
            (id)kSecAttrAccount: acct,
            (id)kSecReturnData: @YES,
        };
        CFTypeRef result = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        if (status != errSecSuccess || !result) {
            // Only errSecItemNotFound actually means "no MEK stored" — the
            // old catch-all message told a user whose key EXISTS to consider
            // re-running "jit vault init" (a real incident: errSecAuthFailed,
            // -25293, from macOS's per-code-signature keychain ACL after the
            // on-disk binary was replaced underneath the running agent, was
            // reported as "key not found"). Access-denied gets its own
            // message naming the actual fix.
            if (status == errSecItemNotFound) {
                r.error_message = dupNSString(@"no master key stored in the keychain — was \"jit vault init\" run?");
            } else if (status == errSecAuthFailed) {
                r.error_message = dupNSString([NSString stringWithFormat:@"macOS denied this process access to the master key (OSStatus=%d) — the jit binary usually changed since this process started (or its keychain approval was declined); restart it on the current binary (`jit agent install` for the agent) and approve the keychain dialog", (int)status]);
            } else {
                r.error_message = dupNSString([NSString stringWithFormat:@"reading the master key from the keychain failed, OSStatus=%d", (int)status]);
            }
            return r;
        }
        NSData *data = (__bridge_transfer NSData *)result;
        *key_len = (int)data.length;
        unsigned char *buf = malloc(*key_len);
        memcpy(buf, data.bytes, *key_len);
        *key = buf;
        r.success = 1;
    }
    return r;
}

KWResult kw_delete_mek(const char *service, const char *account) {
    KWResult r = {0, NULL};
    @autoreleasepool {
        NSString *svc = [NSString stringWithUTF8String:service];
        NSString *acct = [NSString stringWithUTF8String:account];
        NSDictionary *query = @{
            (id)kSecClass: (id)kSecClassGenericPassword,
            (id)kSecAttrService: svc,
            (id)kSecAttrAccount: acct,
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

KWResult kw_set_mek(const char *service, const char *account, const unsigned char *key, int key_len) {
    KWResult r = {0, NULL};
    @autoreleasepool {
        NSString *svc = [NSString stringWithUTF8String:service];
        NSString *acct = [NSString stringWithUTF8String:account];
        NSData *keyData = [NSData dataWithBytes:key length:(NSUInteger)key_len];

        NSDictionary *query = @{
            (id)kSecClass: (id)kSecClassGenericPassword,
            (id)kSecAttrService: svc,
            (id)kSecAttrAccount: acct,
        };
        // Replace-then-add, not SecItemUpdate: identical outcome for the
        // promote step either way, and this reuses the exact add-shape
        // kw_ensure_mek already uses (same accessibility attribute, same
        // plain-item posture) rather than a second code path to keep in sync.
        OSStatus delStatus = SecItemDelete((__bridge CFDictionaryRef)query);
        if (delStatus != errSecSuccess && delStatus != errSecItemNotFound) {
            r.error_message = dupNSString([NSString stringWithFormat:@"replacing existing key failed, OSStatus=%d", (int)delStatus]);
            return r;
        }

        NSDictionary *addQuery = @{
            (id)kSecClass: (id)kSecClassGenericPassword,
            (id)kSecAttrService: svc,
            (id)kSecAttrAccount: acct,
            (id)kSecValueData: keyData,
            (id)kSecAttrAccessible: (id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        };
        OSStatus addStatus = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
        if (addStatus != errSecSuccess) {
            r.error_message = dupNSString([NSString stringWithFormat:@"storing key in keychain failed, OSStatus=%d", (int)addStatus]);
            return r;
        }
        r.success = 1;
    }
    return r;
}
