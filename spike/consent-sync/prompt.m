// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "prompt.h"

static LAContext *current;   // the prompt in flight, guarded by @synchronized(lock)
static BOOL cancelEarly;     // a cancel that beat the prompt
static NSObject *lock;

int64_t spike_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static char *cdup(NSString *s) { return s ? strdup(s.UTF8String) : NULL; }

// arm registers ctx as the prompt in flight. It returns NO when a cancel
// already arrived, so the caller never raises a dialog nobody wants.
static BOOL arm(LAContext *ctx) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{ lock = [NSObject new]; });
    @synchronized (lock) {
        if (cancelEarly) {
            cancelEarly = NO;
            return NO;
        }
        current = ctx;
        return YES;
    }
}

static void disarm(void) {
    @synchronized (lock) {
        current = nil;
    }
}

void cancel_prompt(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{ lock = [NSObject new]; });
    LAContext *ctx;
    @synchronized (lock) {
        ctx = current;
        if (!ctx) cancelEarly = YES;
    }
    [ctx invalidate];
}

static PromptResult cancelledBeforeStart(void) {
    PromptResult r = {0, LAErrorAppCancel, strdup("spike"), strdup("cancelled before the prompt started"), spike_now_ns(), spike_now_ns()};
    return r;
}

PromptResult prompt_keychain(const char *reason) {
    @autoreleasepool {
        LAContext *ctx = [LAContext new];
        if (!arm(ctx)) return cancelledBeforeStart();
        __block PromptResult r = {0, 0, NULL, NULL, 0, 0};
        dispatch_semaphore_t done = dispatch_semaphore_create(0);
        r.start_ns = spike_now_ns();
        [ctx evaluatePolicy:LAPolicyDeviceOwnerAuthentication
            localizedReason:[NSString stringWithUTF8String:reason]
                      reply:^(BOOL success, NSError *error) {
            r.end_ns = spike_now_ns();
            r.ok = success;
            if (error) {
                r.code = error.code;
                r.domain = cdup(error.domain);
                r.msg = cdup(error.localizedDescription);
            }
            dispatch_semaphore_signal(done);
        }];
        dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 130 * NSEC_PER_SEC));
        disarm();
        return r;
    }
}

PromptResult prompt_enclave(const char *reason) {
    @autoreleasepool {
        PromptResult r = {0, 0, NULL, NULL, 0, 0};
        LAContext *ctx = [LAContext new];
        ctx.localizedReason = [NSString stringWithUTF8String:reason];

        CFErrorRef e = NULL;
        SecAccessControlRef ac = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAccessControlPrivateKeyUsage | kSecAccessControlUserPresence, &e);
        if (!ac) {
            r.msg = cdup([NSString stringWithFormat:@"access control: %@", (__bridge NSError *)e]);
            return r;
        }
        // The context rides on the key, the way CryptoKit's
        // SecureEnclave keys take an authenticationContext: every use of
        // this key prompts through ctx, so invalidating ctx is what should
        // take the dialog down. Whether it does is the question.
        NSDictionary *attrs = @{
            (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecAttrKeySizeInBits: @256,
            (id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave,
            (id)kSecUseAuthenticationContext: ctx,
            (id)kSecPrivateKeyAttrs: @{
                (id)kSecAttrIsPermanent: @NO,
                (id)kSecAttrAccessControl: (__bridge id)ac,
            },
        };
        SecKeyRef key = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &e);
        CFRelease(ac);
        if (!key) {
            r.msg = cdup([NSString stringWithFormat:@"enclave key: %@", (__bridge NSError *)e]);
            return r;
        }
        // Sealing uses only the public half and never prompts (the
        // secure-enclave-mek spike, S1b), so the dialog is the open's.
        SecKeyRef pub = SecKeyCopyPublicKey(key);
        const SecKeyAlgorithm alg = kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM;
        uint8_t mek[32] = {0};
        CFDataRef ct = SecKeyCreateEncryptedData(pub, alg, (__bridge CFDataRef)[NSData dataWithBytes:mek length:32], &e);
        CFRelease(pub);
        if (!ct) {
            CFRelease(key);
            r.msg = cdup([NSString stringWithFormat:@"seal: %@", (__bridge NSError *)e]);
            return r;
        }
        if (!arm(ctx)) {
            CFRelease(ct);
            CFRelease(key);
            return cancelledBeforeStart();
        }
        r.start_ns = spike_now_ns();
        CFDataRef pt = SecKeyCreateDecryptedData(key, alg, ct, &e);
        r.end_ns = spike_now_ns();
        disarm();
        CFRelease(ct);
        CFRelease(key);
        if (pt) {
            CFRelease(pt);
            r.ok = 1;
            return r;
        }
        NSError *err = (__bridge_transfer NSError *)e;
        r.code = err.code;
        r.domain = cdup(err.domain);
        r.msg = cdup(err.localizedDescription);
        return r;
    }
}
