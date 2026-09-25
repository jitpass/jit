// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// S2 (the prompt) and S4 (the locked screen), from the signed test bundle.
// Test tags only (com.jitpass.spike.*); every command deletes what it made.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <CoreGraphics/CoreGraphics.h>

static NSString *const kGroup = @"CZC6BH93GJ.com.jitpass.vault";
#define kAlg kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM

static double now(void) { return [NSDate date].timeIntervalSince1970; }
static NSData *tagData(NSString *t) { return [t dataUsingEncoding:NSUTF8StringEncoding]; }

static NSMutableDictionary *query(NSString *tag) {
    return [@{
        (id)kSecClass: (id)kSecClassKey,
        (id)kSecAttrApplicationTag: tagData(tag),
        (id)kSecAttrAccessGroup: kGroup,
        (id)kSecUseDataProtectionKeychain: @YES,
        (id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave,
    } mutableCopy];
}

static OSStatus del(NSString *tag) { return SecItemDelete((__bridge CFDictionaryRef)query(tag)); }

static SecKeyRef make(NSString *tag, CFStringRef accessible, SecAccessControlCreateFlags flags, NSString **err) {
    del(tag);
    CFErrorRef e = NULL;
    SecAccessControlRef ac = SecAccessControlCreateWithFlags(NULL, accessible, flags, &e);
    if (!ac) { *err = [(__bridge NSError *)e description]; return NULL; }
    NSDictionary *attrs = @{
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom, (id)kSecAttrKeySizeInBits: @256,
        (id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave, (id)kSecUseDataProtectionKeychain: @YES,
        (id)kSecAttrAccessGroup: kGroup,
        (id)kSecPrivateKeyAttrs: @{ (id)kSecAttrIsPermanent: @YES, (id)kSecAttrApplicationTag: tagData(tag),
                                    (id)kSecAttrAccessControl: (__bridge id)ac },
    };
    SecKeyRef k = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &e);
    CFRelease(ac);
    if (!k) *err = [(__bridge NSError *)e description];
    return k;
}

static NSData *sealTo(SecKeyRef k, NSData *pt) {
    SecKeyRef pub = SecKeyCopyPublicKey(k);
    NSData *ct = (__bridge_transfer NSData *)SecKeyCreateEncryptedData(pub, kAlg, (__bridge CFDataRef)pt, NULL);
    CFRelease(pub);
    return ct;
}

// Look the key up (optionally carrying an LAContext) and open ct with it.
static NSString *lookupOpen(NSString *tag, LAContext *ctx, NSData *ct, NSData *want) {
    NSMutableDictionary *q = query(tag);
    q[(id)kSecReturnRef] = @YES;
    if (ctx) q[(id)kSecUseAuthenticationContext] = ctx;
    CFTypeRef ref = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &ref);
    if (st != errSecSuccess) return [NSString stringWithFormat:@"lookup failed %d", (int)st];
    CFErrorRef e = NULL;
    NSData *pt = (__bridge_transfer NSData *)SecKeyCreateDecryptedData((SecKeyRef)ref, kAlg, (__bridge CFDataRef)ct, &e);
    CFRelease(ref);
    if (!pt) return [NSString stringWithFormat:@"open failed %ld", (long)((__bridge NSError *)e).code];
    return [pt isEqualToData:want] ? @"ok" : @"WRONG BYTES";
}

static BOOL screenLocked(void) {
    CFDictionaryRef d = CGSessionCopyCurrentDictionary();
    if (!d) return NO;
    BOOL locked = [((__bridge NSDictionary *)d)[@"CGSSessionScreenIsLocked"] boolValue];
    CFRelease(d);
    return locked;
}

static int s2(NSString *reason) {
    NSString *tag = @"com.jitpass.spike.s2", *err = nil;
    SecKeyRef k = make(tag, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                       kSecAccessControlPrivateKeyUsage | kSecAccessControlUserPresence, &err);
    if (!k) { printf("FAIL create: %s\n", err.UTF8String); return 1; }
    CFRelease(k);
    uint8_t b[32]; arc4random_buf(b, 32);
    NSData *mek = [NSData dataWithBytes:b length:32];
    SecKeyRef k2 = NULL;
    { NSMutableDictionary *q = query(tag); q[(id)kSecReturnRef] = @YES;
      SecItemCopyMatching((__bridge CFDictionaryRef)q, (CFTypeRef *)&k2); }
    NSData *ct = sealTo(k2, mek); CFRelease(k2);
    printf("reason (%lu chars): %s\n", (unsigned long)reason.length, reason.UTF8String);

    LAContext *ctx = [LAContext new];
    ctx.localizedReason = reason;
    printf(">>> PROMPT 1 expected now\n"); fflush(stdout);
    double t = now();
    NSString *r1 = lookupOpen(tag, ctx, ct, mek);
    printf("open 1 (fresh context): %s in %.2fs\n", r1.UTF8String, now() - t);
    t = now();
    NSString *r2 = lookupOpen(tag, ctx, ct, mek);
    printf("open 2 (SAME context):  %s in %.3fs  <- under 0.1s means no second prompt\n", r2.UTF8String, now() - t);
    LAContext *fresh = [LAContext new];
    fresh.localizedReason = @"spike S2: a second, separate approval (expected)";
    printf(">>> PROMPT 2 expected now (new context)\n"); fflush(stdout);
    t = now();
    NSString *r3 = lookupOpen(tag, fresh, ct, mek);
    printf("open 3 (new context):   %s in %.2fs\n", r3.UTF8String, now() - t);
    printf("delete: %d\n", (int)del(tag));
    return 0;
}

static int s4(int seconds) {
    NSString *err = nil;
    NSString *after = @"com.jitpass.spike.s4.after", *when = @"com.jitpass.spike.s4.when";
    SecKeyRef a = make(after, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, kSecAccessControlPrivateKeyUsage, &err);
    if (!a) { printf("FAIL create after: %s\n", err.UTF8String); return 1; }
    SecKeyRef w = make(when, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecAccessControlPrivateKeyUsage, &err);
    if (!w) { printf("FAIL create when: %s\n", err.UTF8String); return 1; }
    uint8_t b[32]; arc4random_buf(b, 32);
    NSData *mek = [NSData dataWithBytes:b length:32];
    NSData *ca = sealTo(a, mek), *cw = sealTo(w, mek);
    CFRelease(a); CFRelease(w);
    printf("time      screen    AfterFirstUnlock   WhenUnlocked\n"); fflush(stdout);
    double end = now() + seconds;
    while (now() < end) {
        NSString *ra = lookupOpen(after, nil, ca, mek), *rw = lookupOpen(when, nil, cw, mek);
        NSDateFormatter *f = [NSDateFormatter new]; f.dateFormat = @"HH:mm:ss";
        printf("%s  %-8s  %-17s  %s\n", [f stringFromDate:[NSDate date]].UTF8String,
               screenLocked() ? "LOCKED" : "unlocked", ra.UTF8String, rw.UTF8String);
        fflush(stdout);
        sleep(3);
    }
    printf("delete: %d %d\n", (int)del(after), (int)del(when));
    return 0;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSString *cmd = argc > 1 ? @(argv[1]) : @"";
        if ([cmd isEqual:@"s2"]) return s2(argc > 2 ? @(argv[2]) : @"unlock jit vault (spike S2)");
        if ([cmd isEqual:@"s4"]) return s4(argc > 2 ? atoi(argv[2]) : 90);
        printf("usage: probe s2 [reason] | s4 [seconds]\n");
        return 2;
    }
}
