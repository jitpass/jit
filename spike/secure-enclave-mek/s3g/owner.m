// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// S3g: can the helper-bundle jit DELETE a login-keychain item an old,
// bare-signed jit created? On hardware it could read the vault key but
// SecItemDelete answered errSecInvalidOwnerEdit (-25244), which left the
// key move unfinished. This program makes a TEST-ONLY item the way
// keychainwrap's kw_ensure_mek does and tries every way to remove it.
//
// Every operation runs with user interaction DISALLOWED unless the verb ends
// in "-ui", so a would-be dialog comes back as errSecInteractionNotAllowed
// (-25308) instead of appearing. Only the TEST-ONLY service below is ever
// touched; the program refuses any other.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <stdio.h>
#include <string.h>
#include <spawn.h>
#include <sys/wait.h>

#pragma clang diagnostic ignored "-Wdeprecated-declarations"

extern char **environ;
// SPI (SecTrustedApplicationPriv.h): the code requirement a trusted app
// entry holds.
extern OSStatus SecTrustedApplicationCopyRequirement(SecTrustedApplicationRef, SecRequirementRef *);

static NSString *const kService = @"com.jitpass.spike.owner.TEST-ONLY";
static NSString *kAccount = @"s3g";

static NSDictionary *baseQuery(void) {
    return @{ (id)kSecClass: (id)kSecClassGenericPassword,
              (id)kSecAttrService: kService, (id)kSecAttrAccount: kAccount };
}

static const char *name(OSStatus st) {
    switch (st) {
    case errSecSuccess: return "OK";
    case errSecItemNotFound: return "errSecItemNotFound";
    case errSecInteractionNotAllowed: return "errSecInteractionNotAllowed (would have shown a dialog)";
    case errSecAuthFailed: return "errSecAuthFailed";
    case errSecInvalidOwnerEdit: return "errSecInvalidOwnerEdit";
    case errSecUserCanceled: return "errSecUserCanceled";
    case errSecMissingEntitlement: return "errSecMissingEntitlement";
    case errSecNoAccessForItem: return "errSecNoAccessForItem";
    case errSecDuplicateItem: return "errSecDuplicateItem";
    }
    return "other";
}

static int report(const char *op, OSStatus st) {
    printf("%-14s OSStatus=%d  %s\n", op, (int)st, name(st));
    return st == errSecSuccess ? 0 : 1;
}

// create: kw_ensure_mek's exact add.
static int create(void) {
    uint8_t b[32]; arc4random_buf(b, sizeof b);
    NSMutableDictionary *q = [baseQuery() mutableCopy];
    q[(id)kSecAttrAccessible] = (id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
    q[(id)kSecValueData] = [NSData dataWithBytes:b length:sizeof b];
    return report("create", SecItemAdd((__bridge CFDictionaryRef)q, NULL));
}

static int readData(void) {
    NSMutableDictionary *q = [baseQuery() mutableCopy];
    q[(id)kSecReturnData] = @YES;
    CFTypeRef data = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &data);
    if (data) CFRelease(data);
    return report("read", st);
}

static int present(void) {
    return report("present", SecItemCopyMatching((__bridge CFDictionaryRef)baseQuery(), NULL));
}

// delete: kw_delete_mek's exact call.
static int deleteItem(void) {
    return report("SecItemDelete", SecItemDelete((__bridge CFDictionaryRef)baseQuery()));
}

// SecItemDelete with the modern "you may ask" flags.
static int deleteAuthUI(void) {
    NSMutableDictionary *q = [baseQuery() mutableCopy];
    q[(id)kSecUseAuthenticationUI] = (id)kSecUseAuthenticationUIAllow;
    q[(id)kSecUseOperationPrompt] = @"remove the old copy of the TEST-ONLY key";
    return report("delete+authUI", SecItemDelete((__bridge CFDictionaryRef)q));
}

static SecKeychainItemRef copyRef(OSStatus *st) {
    NSMutableDictionary *q = [baseQuery() mutableCopy];
    q[(id)kSecReturnRef] = @YES;
    CFTypeRef ref = NULL;
    *st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &ref);
    return (SecKeychainItemRef)ref;
}

// The legacy call on the item reference.
static int deleteRef(void) {
    OSStatus st;
    SecKeychainItemRef item = copyRef(&st);
    if (!item) return report("copy ref", st);
    st = SecKeychainItemDelete(item);
    CFRelease(item);
    return report("ItemDelete(ref)", st);
}

// SecItemUpdate of the data: what kw_set_mek could do instead of delete+add.
static int update(void) {
    uint8_t b[32]; arc4random_buf(b, sizeof b);
    NSDictionary *attrs = @{ (id)kSecValueData: [NSData dataWithBytes:b length:sizeof b] };
    return report("SecItemUpdate", SecItemUpdate((__bridge CFDictionaryRef)baseQuery(), (__bridge CFDictionaryRef)attrs));
}

// Apple's own tool, as a child process (its own signature, "apple-tool:").
static int tool(void) {
    const char *argv[] = { "/usr/bin/security", "delete-generic-password",
        "-s", [kService UTF8String], "-a", [kAccount UTF8String], NULL };
    pid_t pid;
    int rc = posix_spawn(&pid, argv[0], NULL, NULL, (char *const *)argv, environ);
    if (rc != 0) { printf("tool: spawn failed %d\n", rc); return 1; }
    int status = 0;
    waitpid(pid, &status, 0);
    printf("%-14s exit=%d\n", "security tool", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 1;
}

// acl: the item's access list, TEST-ONLY item only. Metadata; no secret.
static int acl(void) {
    OSStatus st;
    SecKeychainItemRef item = copyRef(&st);
    if (!item) return report("copy ref", st);
    SecAccessRef access = NULL;
    st = SecKeychainItemCopyAccess(item, &access);
    CFRelease(item);
    if (st) return report("copy access", st);
    CFArrayRef list = NULL;
    SecAccessCopyACLList(access, &list);
    for (CFIndex i = 0; list && i < CFArrayGetCount(list); i++) {
        SecACLRef a = (SecACLRef)CFArrayGetValueAtIndex(list, i);
        CFArrayRef auths = SecACLCopyAuthorizations(a);
        CFArrayRef apps = NULL; CFStringRef desc = NULL;
        SecKeychainPromptSelector sel = 0;
        SecACLCopyContents(a, &apps, &desc, &sel);
        NSString *d = (__bridge NSString *)desc;
        // The partition list's description is a hex-encoded plist.
        if ([(__bridge NSArray *)auths containsObject:(id)kSecACLAuthorizationPartitionID] && d.length % 2 == 0) {
            NSMutableData *raw = [NSMutableData data];
            for (NSUInteger j = 0; j + 1 < d.length; j += 2) {
                unsigned v; [[NSScanner scannerWithString:[d substringWithRange:NSMakeRange(j, 2)]] scanHexInt:&v];
                uint8_t c = v; [raw appendBytes:&c length:1];
            }
            id pl = [NSPropertyListSerialization propertyListWithData:raw options:0 format:NULL error:NULL];
            if (pl) d = [pl description];
        }
        printf("ACL %ld auths=%s\n  desc=%s\n  apps=", (long)i,
            [[(__bridge NSArray *)auths componentsJoinedByString:@","] UTF8String], [d UTF8String]);
        if (!apps) printf("(any application)");
        for (CFIndex k = 0; apps && k < CFArrayGetCount(apps); k++) {
            SecTrustedApplicationRef t = (SecTrustedApplicationRef)CFArrayGetValueAtIndex(apps, k);
            CFDataRef path = NULL;
            SecTrustedApplicationCopyData(t, &path);
            SecRequirementRef req = NULL; CFStringRef reqs = NULL;
            if (SecTrustedApplicationCopyRequirement(t, &req) == 0 && req) SecRequirementCopyString(req, 0, &reqs);
            printf("\n    %.*s  [%s]", path ? (int)CFDataGetLength(path) : 0, path ? (const char *)CFDataGetBytePtr(path) : "",
                reqs ? [(__bridge NSString *)reqs UTF8String] : "");
            if (path) CFRelease(path);
            if (reqs) CFRelease(reqs);
            if (req) CFRelease(req);
        }
        printf("\n");
        if (auths) CFRelease(auths);
        if (apps) CFRelease(apps);
        if (desc) CFRelease(desc);
    }
    if (list) CFRelease(list);
    CFRelease(access);
    return 0;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc < 2) { printf("usage: owner VERB [account]\n"); return 2; }
        if (argc > 2) kAccount = [NSString stringWithUTF8String:argv[2]];
        if (![kService containsString:@"TEST-ONLY"]) return 3;
        NSString *verb = [NSString stringWithUTF8String:argv[1]];
        BOOL ui = [verb hasSuffix:@"-ui"];
        if (ui) verb = [verb substringToIndex:verb.length - 3];
        SecKeychainSetUserInteractionAllowed(ui);
        if ([verb isEqual:@"create"]) return create();
        if ([verb isEqual:@"read"]) return readData();
        if ([verb isEqual:@"present"]) return present();
        if ([verb isEqual:@"delete"]) return deleteItem();
        if ([verb isEqual:@"delete-authui"]) return deleteAuthUI();
        if ([verb isEqual:@"delete-ref"]) return deleteRef();
        if ([verb isEqual:@"update"]) return update();
        if ([verb isEqual:@"tool"]) return tool();
        if ([verb isEqual:@"acl"]) return acl();
        return 2;
    }
}
