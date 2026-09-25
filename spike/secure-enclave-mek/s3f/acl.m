// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// S3f: after jit moves into a helper bundle and is re-signed, can it still
// read the login-keychain item an OLD jit created, without the legacy
// "wants to use your confidential information" dialog?
//
// It never shows that dialog: reads run with user interaction disallowed,
// so where macOS would have asked, the read fails with
// errSecInteractionNotAllowed (-25308) instead. Test service only.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <stdio.h>
#include <string.h>

static NSString *const kService = @"com.jitpass.spike.acl.TEST-ONLY";
static NSString *const kAccount = @"s3f";

// The same attributes keychainwrap's kw_ensure_mek uses: a plain
// generic-password item in the file-based login keychain, no access control.
static int create(void) {
    SecItemDelete((__bridge CFDictionaryRef)@{ (id)kSecClass: (id)kSecClassGenericPassword,
        (id)kSecAttrService: kService, (id)kSecAttrAccount: kAccount });
    uint8_t b[32]; arc4random_buf(b, sizeof b);
    OSStatus st = SecItemAdd((__bridge CFDictionaryRef)@{
        (id)kSecClass: (id)kSecClassGenericPassword,
        (id)kSecAttrService: kService, (id)kSecAttrAccount: kAccount,
        (id)kSecAttrAccessible: (id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        (id)kSecValueData: [NSData dataWithBytes:b length:sizeof b],
    }, NULL);
    printf("create: OSStatus=%d\n", (int)st);
    return st == errSecSuccess ? 0 : 1;
}

static int readNoUI(void) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    SecKeychainSetUserInteractionAllowed(false);
#pragma clang diagnostic pop
    CFTypeRef data = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)@{
        (id)kSecClass: (id)kSecClassGenericPassword,
        (id)kSecAttrService: kService, (id)kSecAttrAccount: kAccount,
        (id)kSecReturnData: @YES,
    }, &data);
    if (data) CFRelease(data);
    const char *what = st == errSecSuccess ? "READ OK, no dialog"
        : st == errSecInteractionNotAllowed ? "WOULD HAVE PROMPTED (errSecInteractionNotAllowed)"
        : st == errSecAuthFailed ? "DENIED (errSecAuthFailed)" : "other failure";
    printf("read: OSStatus=%d  %s\n", (int)st, what);
    return st == errSecSuccess ? 0 : 1;
}

static int del(void) {
    OSStatus st = SecItemDelete((__bridge CFDictionaryRef)@{ (id)kSecClass: (id)kSecClassGenericPassword,
        (id)kSecAttrService: kService, (id)kSecAttrAccount: kAccount });
    printf("delete: OSStatus=%d\n", (int)st);
    return 0;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc < 2) { printf("usage: acl create|read|delete\n"); return 2; }
        if (!strcmp(argv[1], "create")) return create();
        if (!strcmp(argv[1], "read")) return readNoUI();
        if (!strcmp(argv[1], "delete")) return del();
        return 2;
    }
}
