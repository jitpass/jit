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

// kwWithoutUI runs block with this process's keychain user interaction
// switched off, then puts back whatever it was. A would-be keychain dialog
// (an access prompt, an unlock prompt) then fails the call inside block with
// errSecInteractionNotAllowed instead of appearing. The setting is
// process-wide, so it is scoped to the few calls that need it and only ever
// used from a CLI command's own thread of work (a delete's fallback, a quiet
// read), never from the long-running service. It affects keychain UI only:
// LocalAuthentication's Touch ID prompt (kw_challenge) and the Secure
// Enclave's own dialog are not keychain UI and are not touched by it. If the
// current value cannot be read, the framework's default (allowed) is what is
// put back.
static void kwWithoutUI(void (^block)(void)) {
    Boolean was = true;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    if (SecKeychainGetUserInteractionAllowed(&was) != errSecSuccess) {
        was = true;
    }
    SecKeychainSetUserInteractionAllowed(false);
    block();
    SecKeychainSetUserInteractionAllowed(was);
#pragma clang diagnostic pop
}

int kw_ui_scope_probe(int start, int *during, int *after) {
    __block Boolean in = true;
    Boolean out = true;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    Boolean orig = true;
    SecKeychainGetUserInteractionAllowed(&orig);
    SecKeychainSetUserInteractionAllowed(start ? true : false);
    kwWithoutUI(^{
        SecKeychainGetUserInteractionAllowed(&in);
    });
    SecKeychainGetUserInteractionAllowed(&out);
    SecKeychainSetUserInteractionAllowed(orig);
#pragma clang diagnostic pop
    *during = in ? 1 : 0;
    *after = out ? 1 : 0;
    return 0;
}

void kw_set_user_interaction(int allowed) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    SecKeychainSetUserInteractionAllowed(allowed ? true : false);
#pragma clang diagnostic pop
}

// kwNoUI marks a query so that anything needing a dialog fails with
// errSecInteractionNotAllowed rather than asking.
static void kwNoUI(NSMutableDictionary *q) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    q[(id)kSecUseAuthenticationUI] = (id)kSecUseAuthenticationUIFail;
#pragma clang diagnostic pop
}

// kwItemQuery is the service/account match every call here starts from.
static NSMutableDictionary *kwItemQuery(NSString *svc, NSString *acct) {
    return [@{
        (id)kSecClass: (id)kSecClassGenericPassword,
        (id)kSecAttrService: svc,
        (id)kSecAttrAccount: acct,
    } mutableCopy];
}

// kwPresenceQuery is kw_mek_present's query: metadata only, one match, and
// no dialog. kSecReturnData is deliberately absent (see kw_mek_present).
static NSMutableDictionary *kwPresenceQuery(NSString *svc, NSString *acct) {
    NSMutableDictionary *q = kwItemQuery(svc, acct);
    q[(id)kSecMatchLimit] = (id)kSecMatchLimitOne;
    kwNoUI(q);
    return q;
}

// kwRefQuery is the delete fallback's lookup: every matching item's
// reference, no dialog, and only in the user's default keychain (the login
// keychain, where SecItemAdd put every vault key), so an item of the same
// name in any other keychain on the search list is never touched. kc is that
// default keychain.
static NSMutableDictionary *kwRefQuery(NSString *svc, NSString *acct, SecKeychainRef kc) {
    NSMutableDictionary *q = kwItemQuery(svc, acct);
    q[(id)kSecReturnRef] = @YES;
    q[(id)kSecMatchLimit] = (id)kSecMatchLimitAll;
    q[(id)kSecMatchSearchList] = @[(__bridge id)kc];
    kwNoUI(q);
    return q;
}

// kwDeleteQuery is kw_item_delete's query: SecItemDelete, no dialog.
static NSMutableDictionary *kwDeleteQuery(NSString *svc, NSString *acct) {
    NSMutableDictionary *q = kwItemQuery(svc, acct);
    kwNoUI(q);
    return q;
}

int kw_query_traits(int which) {
    @autoreleasepool {
        NSMutableDictionary *q = nil;
        SecKeychainRef kc = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        if (SecKeychainCopyDefault(&kc) != errSecSuccess) {
            return -1;
        }
        switch (which) {
        case 0: q = kwPresenceQuery(@"probe", @"probe"); break;
        case 1: q = kwRefQuery(@"probe", @"probe", kc); break;
        case 2: q = kwDeleteQuery(@"probe", @"probe"); break;
        }
        int traits = 0;
        if ([q[(id)kSecUseAuthenticationUI] isEqual:(id)kSecUseAuthenticationUIFail]) traits |= 1;
#pragma clang diagnostic pop
        NSArray *list = q[(id)kSecMatchSearchList];
        if (list.count == 1 && CFEqual((__bridge CFTypeRef)list[0], kc)) traits |= 2;
        if ([q[(id)kSecReturnData] boolValue]) traits |= 4;
        CFRelease(kc);
        return traits;
    }
}

// kwPOSIXENOENT is how macOS reports "the calling process's executable is
// gone" from a keychain lookup. Security.framework maps POSIX errno values
// into OSStatus as kPOSIXErrorBase + errno (kPOSIXErrorBase is 100000), so
// ENOENT arrives as 100002 rather than as any errSec* constant.
//
// It reaches us for one reason, and it is not "the item is missing": macOS
// validates the caller's code signature against its on-disk binary before
// honouring a keychain ACL, and if that file has been deleted there is
// nothing to read. The long-running service is the process this happens to —
// a jit upgrade that MOVES the binary (the tarball at /usr/local/bin/jit
// giving way to a Homebrew cask at /opt/homebrew/bin/jit) leaves the running
// service holding a path that no longer exists, and every vault write then
// fails.
//
// Grouped with errSecAuthFailed because the user-visible cause and the fix
// are identical — the binary underneath a running process is not the one the
// keychain approved. Only the flavour differs: errSecAuthFailed is a binary
// REPLACED in place, this is one REMOVED. Reported as a bare number until
// 2026-08-09, when a real machine hit it during exactly the tarball-to-cask
// move the 0.82.0 release introduced.
//
// Spelled out rather than including <MacTypes.h> for kPOSIXErrorBase: one
// constant used once, and the arithmetic is the documentation.
static const OSStatus kwPOSIXENOENT = 100000 + 2;

KWResult kw_fetch_mek(const char *service, const char *account, unsigned char **key, int *key_len, int quiet) {
    KWResult r = {0, NULL};
    @autoreleasepool {
        NSString *svc = [NSString stringWithUTF8String:service];
        NSString *acct = [NSString stringWithUTF8String:account];

        NSMutableDictionary *query = kwItemQuery(svc, acct);
        query[(id)kSecReturnData] = @YES;
        __block CFTypeRef result = NULL;
        __block OSStatus status;
        if (quiet) {
            // A read that must not ask (keystore's check of a leftover key
            // at `jit vault init`): a dialog fails the read instead.
            kwNoUI(query);
            kwWithoutUI(^{
                status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
            });
        } else {
            status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        }
        if (status != errSecSuccess || !result) {
            if (result) CFRelease(result);
            // Only errSecItemNotFound actually means "no MEK stored" — the
            // old catch-all message told a user whose key EXISTS to consider
            // re-running "jit vault init" (a real incident: errSecAuthFailed,
            // -25293, from macOS's per-code-signature keychain ACL after the
            // on-disk binary was replaced underneath the running agent, was
            // reported as "key not found"). Access-denied gets its own
            // message naming the actual fix.
            if (status == errSecItemNotFound) {
                // States the remedy rather than asking the reader a rhetorical
                // question: this was the only "was X run?" phrasing in jit,
                // next to three siblings that all name the command. The
                // backticks are what the CLI's error printer renders cyan.
                r.error_message = dupNSString(@"no master key stored in the keychain, run `jit vault init` first");
            } else if (status == errSecAuthFailed || status == kwPOSIXENOENT) {
                r.error_message = dupNSString([NSString stringWithFormat:@"macOS denied this process access to the master key (OSStatus=%d) — the jit binary this process is running usually changed or was removed since it started (or its keychain approval was declined); run `jit service restart` and approve the keychain dialog", (int)status]);
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

int kw_mek_present(const char *service, const char *account) {
    @autoreleasepool {
        NSString *svc = [NSString stringWithUTF8String:service];
        NSString *acct = [NSString stringWithUTF8String:account];

        // Existence only: kSecReturnData is deliberately absent, so this reads
        // the item's METADATA, never its protected bytes. The login keychain's
        // per-code-signature "allow access" ACL dialog that kw_fetch_mek can
        // raise guards the item's DATA, not its presence, so a metadata-only
        // query never triggers it — which is the whole point here: `jit doctor`
        // could not run its master-key probe on a non-interactive run precisely
        // because the data-reading check might block on that dialog, and this
        // one cannot. (kSecReturnData omitted is load-bearing; do not add it.)
        // kSecUseAuthenticationUIFail (kwPresenceQuery) covers what is left, a
        // keychain that would have to ask to be searched at all (a locked
        // one): the query fails with errSecInteractionNotAllowed instead, and
        // the caller reads that as indeterminate.
        //
        // Returns the raw OSStatus; keychainwrap.presenceFromStatus maps it.
        return (int)SecItemCopyMatching((__bridge CFDictionaryRef)kwPresenceQuery(svc, acct), NULL);
    }
}

int kw_item_delete(const char *service, const char *account) {
    @autoreleasepool {
        NSMutableDictionary *q = kwDeleteQuery([NSString stringWithUTF8String:service],
                                               [NSString stringWithUTF8String:account]);
        return (int)SecItemDelete((__bridge CFDictionaryRef)q);
    }
}

// kw_item_delete_by_ref is the one fallback deleteItem (keychainwrap.go)
// takes, on exactly errSecInvalidOwnerEdit, for one measured case
// (spike/secure-enclave-mek/FINDINGS.md, S3g). In the file-based login
// keychain, SecItemDelete answers errSecInvalidOwnerEdit (-25244) to any
// process that is not the executable, at the same PATH, that created the
// item: the JitPass Agent helper could read the vault key an older jit had
// made (same identifier, same team), yet could not delete it, and the move
// into the Secure Enclave stopped one step from done. SecKeychainItemDelete
// on the item's reference removes it with no dialog. It is the legacy API,
// deprecated since macOS 10.10 and still the one that works on a
// legacy-keychain item; it is used for nothing else.
//
// No dialog, by construction rather than by measurement alone: the lookup
// carries kSecUseAuthenticationUIFail and searches only the default (login)
// keychain (kwRefQuery), and both the lookup and each delete run with the
// process's keychain interaction off (kwWithoutUI).
//
// Returns the lookup's status when it fails (errSecItemNotFound included:
// the caller decides what an empty lookup means, and it is not "deleted"),
// else the first failing delete's, else errSecSuccess.
int kw_item_delete_by_ref(const char *service, const char *account) {
    __block OSStatus out = errSecSuccess;
    @autoreleasepool {
        NSString *svc = [NSString stringWithUTF8String:service];
        NSString *acct = [NSString stringWithUTF8String:account];
        SecKeychainRef kc = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        OSStatus kcStatus = SecKeychainCopyDefault(&kc);
        if (kcStatus != errSecSuccess || !kc) {
            return kcStatus != errSecSuccess ? (int)kcStatus : (int)errSecNoDefaultKeychain;
        }
        NSDictionary *q = kwRefQuery(svc, acct, kc);
        kwWithoutUI(^{
            CFTypeRef result = NULL;
            OSStatus find = SecItemCopyMatching((__bridge CFDictionaryRef)q, &result);
            if (find != errSecSuccess || !result) {
                if (result) CFRelease(result);
                out = find != errSecSuccess ? find : errSecItemNotFound;
                return;
            }
            NSArray *refs = (__bridge_transfer NSArray *)result;
            if (![refs isKindOfClass:[NSArray class]] || refs.count == 0) {
                out = errSecItemNotFound;
                return;
            }
            for (id ref in refs) {
                if (CFGetTypeID((__bridge CFTypeRef)ref) != SecKeychainItemGetTypeID()) {
                    if (out == errSecSuccess) out = errSecInvalidItemRef;
                    continue;
                }
                OSStatus d = SecKeychainItemDelete((__bridge SecKeychainItemRef)ref);
                if (d != errSecSuccess && out == errSecSuccess) {
                    out = d;
                }
            }
        });
        CFRelease(kc);
#pragma clang diagnostic pop
    }
    return (int)out;
}

KWResult kw_add_mek(const char *service, const char *account, const unsigned char *key, int key_len) {
    KWResult r = {0, NULL};
    @autoreleasepool {
        NSData *keyData = [NSData dataWithBytes:key length:(NSUInteger)key_len];
        // The exact add-shape kw_ensure_mek uses (same accessibility
        // attribute, same plain-item posture), so a replaced key is stored
        // the way a created one is.
        NSDictionary *addQuery = @{
            (id)kSecClass: (id)kSecClassGenericPassword,
            (id)kSecAttrService: [NSString stringWithUTF8String:service],
            (id)kSecAttrAccount: [NSString stringWithUTF8String:account],
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

KWResult kw_list_accounts(const char *service, char ***accounts, int *count) {
    KWResult r = {0, NULL};
    *accounts = NULL;
    *count = 0;
    @autoreleasepool {
        NSDictionary *query = @{
            (id)kSecClass: (id)kSecClassGenericPassword,
            (id)kSecAttrService: [NSString stringWithUTF8String:service],
            (id)kSecReturnAttributes: @YES,
            (id)kSecMatchLimit: (id)kSecMatchLimitAll,
        };
        CFTypeRef result = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        if (status == errSecItemNotFound) {
            r.success = 1;
            return r;
        }
        if (status != errSecSuccess || !result) {
            r.error_message = dupNSString([NSString stringWithFormat:@"listing keychain items failed, OSStatus=%d", (int)status]);
            return r;
        }
        NSArray *items = (__bridge_transfer NSArray *)result;
        char **out = calloc(items.count ? items.count : 1, sizeof(char *));
        if (!out) {
            r.error_message = dupNSString(@"listing keychain items: out of memory");
            return r;
        }
        int n = 0;
        for (NSDictionary *item in items) {
            NSString *acct = item[(id)kSecAttrAccount];
            if ([acct isKindOfClass:[NSString class]]) out[n++] = dupNSString(acct);
        }
        *accounts = out;
        *count = n;
        r.success = 1;
    }
    return r;
}
