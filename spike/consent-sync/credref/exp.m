// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0
//
// Experiment for FINDINGS.md, "A key from the keychain": does invalidating an LAContext take
// the dialog down when the key only carries the context's credential
// reference (what a key from SecItemCopyMatching may carry), and does
// evaluating the access control first fix it?
// usage: exp <object|credref> <direct|evalfirst> <cancel|approve>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <objc/message.h>

static long long ms(void) { return (long long)([[NSDate date] timeIntervalSince1970] * 1000); }
static void say(NSString *s) { printf("%lld %s\n", ms(), s.UTF8String); fflush(stdout); }

int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc < 4) return 2;
        NSString *binding = @(argv[1]), *flow = @(argv[2]), *action = @(argv[3]);
        LAContext *ctx = [LAContext new];
        NSString *reason = [NSString stringWithFormat:@"run a jit test (%@, %@): %@", binding, flow,
                            [action isEqual:@"cancel"] ? @"do not answer" : @"approve it"];
        ctx.localizedReason = reason;
        CFErrorRef e = NULL;
        SecAccessControlRef ac = SecAccessControlCreateWithFlags(NULL, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAccessControlPrivateKeyUsage | kSecAccessControlUserPresence, &e);
        NSMutableDictionary *attrs = [@{
            (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecAttrKeySizeInBits: @256,
            (id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave,
            (id)kSecPrivateKeyAttrs: @{ (id)kSecAttrIsPermanent: @NO, (id)kSecAttrAccessControl: (__bridge id)ac },
        } mutableCopy];
        if ([binding isEqual:@"object"]) {
            attrs[(id)kSecUseAuthenticationContext] = ctx;
        } else {
            NSData *ext = ((NSData *(*)(id, SEL))objc_msgSend)(ctx, NSSelectorFromString(@"externalizedContext"));
            if (!ext) { say(@"no externalized context"); return 1; }
            attrs[@"u_CredRef"] = ext;
        }
        SecKeyRef key = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &e);
        if (!key) { say([NSString stringWithFormat:@"key: %@", (__bridge NSError *)e]); return 1; }
        SecKeyRef pub = SecKeyCopyPublicKey(key);
        const SecKeyAlgorithm alg = kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM;
        uint8_t zero[32] = {0};
        CFDataRef ct = SecKeyCreateEncryptedData(pub, alg, (__bridge CFDataRef)[NSData dataWithBytes:zero length:32], &e);
        if (!ct) { say(@"seal failed"); return 1; }

        if ([action isEqual:@"cancel"]) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1500 * NSEC_PER_MSEC),
                           dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                say(@"invalidate");
                [ctx invalidate];
                say(@"invalidate_returned");
            });
        }
        if ([flow isEqual:@"evalfirst"]) {
            // The key's own access control, as the enclave completed it.
            NSDictionary *ka = (__bridge_transfer NSDictionary *)SecKeyCopyAttributes(key);
            id kacl = ka[(id)kSecAttrAccessControl];
            say([NSString stringWithFormat:@"key_acl present=%d", kacl != nil]);
            SecAccessControlRef use = kacl ? (__bridge SecAccessControlRef)kacl : ac;
            NSArray *ops = @[@(LAAccessControlOperationUseKeyDecrypt), @(LAAccessControlOperationUseKeyKeyExchange), @(LAAccessControlOperationUseKeySign)];
            BOOL passed = NO;
            for (NSNumber *op in ops) {
                dispatch_semaphore_t done = dispatch_semaphore_create(0);
                __block BOOL ok = NO;
                __block NSError *err = nil;
                say([NSString stringWithFormat:@"evaluate_start op=%@", op]);
                [ctx evaluateAccessControl:use operation:op.integerValue localizedReason:reason
                                     reply:^(BOOL success, NSError *error) { ok = success; err = error; dispatch_semaphore_signal(done); }];
                dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 60 * NSEC_PER_SEC));
                say([NSString stringWithFormat:@"evaluate_end op=%@ ok=%d code=%ld %@", op, ok, (long)err.code, err.localizedDescription ?: @""]);
                if (ok) { passed = YES; break; }
                if (err.code != -1009) return 0; // a real answer (cancel), not "this operation is not in the ACL"
            }
            if (!passed) return 0;
        }
        say(@"decrypt_start");
        CFDataRef pt = SecKeyCreateDecryptedData(key, alg, ct, &e);
        NSError *err = (__bridge_transfer NSError *)e;
        say([NSString stringWithFormat:@"decrypt_end ok=%d code=%ld %@ %@", pt != NULL, (long)err.code, err.domain ?: @"", err.localizedDescription ?: @""]);
        return 0;
    }
}
