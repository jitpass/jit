#import "keychain.h"
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <string.h>
#import <stdlib.h>
#import <pthread.h>
#import <unistd.h>

static OSStatus kwCopyMatching(int which, NSString *svc, NSString *acct, SecKeychainRef kc, CFTypeRef *result);
static OSStatus kwCopyMatchingIn(int which, NSString *svc, NSString *acct, SecKeychainRef kc, SecKeychainRef only, CFTypeRef *result);
static OSStatus kwDeleteItemIn(int which, NSString *svc, NSString *acct, SecKeychainRef only);

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

        OSStatus existsStatus = kwCopyMatching(KW_Q_EXISTS, svc, acct, NULL, NULL);
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
// errSecInteractionNotAllowed instead of appearing. It affects keychain UI
// only: LocalAuthentication's Touch ID prompt (kw_challenge) and the Secure
// Enclave's own dialog are not keychain UI and are not touched by it.
//
// The setting is PROCESS-WIDE, so two rules keep it safe:
//
//   - Only CLI commands reach it: the quiet read (CountOpens, at `jit vault
//     init` and the --force check of `jit vault rekey --wrapper
//     secure-enclave`; MatchesMEK and InstallMEK, the move's comparisons)
//     and the reference delete, which keychainwrap's
//     deleteItem takes only when its caller asked for the CLI fallback (the
//     vault key's move, rotation, `jit vault delete`, init). The service's
//     grant and job key deletes take the reference delete without it
//     (kw_item_delete_by_ref_no_switch, from GrantKeys.Delete), so the
//     long-running service never switches keychain UI off for the whole
//     process while other requests run.
//   - Overlapping and nested uses share one save and one restore: a mutex
//     and a depth count. The first to enter saves the value and switches it
//     off; the last to leave puts it back. Without that, two overlapping
//     calls each saved and restored on their own, and the second's save
//     could read the first's "off" and restore it, leaving interaction off
//     for good.
//
// If the current value cannot be read, the framework's default (allowed) is
// what is put back.
static pthread_mutex_t kwUIMu = PTHREAD_MUTEX_INITIALIZER;
static int kwUIDepth = 0;
static Boolean kwUISaved = true;

static void kwWithoutUI(void (^block)(void)) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    pthread_mutex_lock(&kwUIMu);
    if (kwUIDepth++ == 0) {
        Boolean was = true;
        if (SecKeychainGetUserInteractionAllowed(&was) != errSecSuccess) {
            was = true;
        }
        kwUISaved = was;
        SecKeychainSetUserInteractionAllowed(false);
    }
    pthread_mutex_unlock(&kwUIMu);
    block();
    pthread_mutex_lock(&kwUIMu);
    if (--kwUIDepth == 0) {
        SecKeychainSetUserInteractionAllowed(kwUISaved);
    }
    pthread_mutex_unlock(&kwUIMu);
#pragma clang diagnostic pop
}

static Boolean kwUIAllowed(void) {
    Boolean v = true;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    SecKeychainGetUserInteractionAllowed(&v);
#pragma clang diagnostic pop
    return v;
}

int kw_ui_scope_probe(int start, int *during, int *after) {
    __block Boolean in = true;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    Boolean orig = kwUIAllowed();
    SecKeychainSetUserInteractionAllowed(start ? true : false);
    kwWithoutUI(^{
        in = kwUIAllowed();
        // Nested use: still off inside, and the outer scope's restore is
        // the one that counts.
        kwWithoutUI(^{});
        if (kwUIAllowed()) in = true;
    });
    Boolean out = kwUIAllowed();
    SecKeychainSetUserInteractionAllowed(orig);
#pragma clang diagnostic pop
    *during = in ? 1 : 0;
    *after = out ? 1 : 0;
    return 0;
}

int kw_ui_overlap_probe(int usec) {
    __block int ok = 1;
    kwWithoutUI(^{
        if (kwUIAllowed()) ok = 0;
        if (usec > 0) usleep((useconds_t)usec);
        if (kwUIAllowed()) ok = 0;
    });
    return ok;
}

int kw_get_user_interaction(void) {
    return kwUIAllowed() ? 1 : 0;
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

// kwQuery builds every query this file hands SecItemCopyMatching or
// SecItemDelete, by its KW_Q_* number (keychain.h): the registry the traits
// test walks, so a new query is checked from the day it is added. kc is the
// default keychain, for the queries that search only it (nil otherwise; a
// query that needs it and gets none is nil). Nothing else builds a query:
// kwCopyMatching and kwDeleteItem are the only callers of the two Security
// functions, and TestEveryQueryGoesThroughTheRegistry holds that.
static NSMutableDictionary *kwQuery(int which, NSString *svc, NSString *acct, SecKeychainRef kc) {
    NSMutableDictionary *q = [@{
        (id)kSecClass: (id)kSecClassGenericPassword,
        (id)kSecAttrService: svc,
        (id)kSecAttrAccount: acct,
    } mutableCopy];
    switch (which) {
    case KW_Q_PRESENCE:
        // Metadata only, one match, no dialog. kSecReturnData is
        // deliberately absent (see kw_mek_present).
        q[(id)kSecMatchLimit] = (id)kSecMatchLimitOne;
        kwNoUI(q);
        return q;
    case KW_Q_PRESENCE_DEFAULT:
        // KW_Q_PRESENCE over the default keychain only: the check after a
        // reference delete, which deletes only there (KW_Q_REF).
        if (!kc) return nil;
        q[(id)kSecMatchLimit] = (id)kSecMatchLimitOne;
        q[(id)kSecMatchSearchList] = @[(__bridge id)kc];
        kwNoUI(q);
        return q;
    case KW_Q_REF:
        // Every matching item's reference, no dialog, and only in the
        // user's default keychain (the login keychain, where SecItemAdd put
        // every vault key), so an item of the same name in any other
        // keychain on the search list is never touched.
        if (!kc) return nil;
        q[(id)kSecReturnRef] = @YES;
        q[(id)kSecMatchLimit] = (id)kSecMatchLimitAll;
        q[(id)kSecMatchSearchList] = @[(__bridge id)kc];
        kwNoUI(q);
        return q;
    case KW_Q_DELETE:
        kwNoUI(q);
        return q;
    case KW_Q_FETCH_QUIET:
        // The quiet read (CountOpens, MatchesMEK, InstallMEK): the key's
        // bytes, with no dialog.
        q[(id)kSecReturnData] = @YES;
        kwNoUI(q);
        return q;
    case KW_Q_FETCH:
        // The read behind jit's own Touch ID check. It may show the login
        // keychain's "allow access" dialog, which the service's error for
        // a changed binary tells the user to approve; everything that must
        // never ask uses another query.
        q[(id)kSecReturnData] = @YES;
        return q;
    case KW_Q_EXISTS:
        // kw_ensure_mek's check before it adds: existence only.
        return q;
    case KW_Q_LIST:
        // Every account under the service, from metadata: grant key ids.
        [q removeObjectForKey:(id)kSecAttrAccount];
        q[(id)kSecReturnAttributes] = @YES;
        q[(id)kSecMatchLimit] = (id)kSecMatchLimitAll;
        return q;
    }
    return nil;
}

// kwCopyMatchingIn and kwDeleteItemIn hold this file's only
// SecItemCopyMatching and SecItemDelete calls, each over a registry query.
// only, when set, narrows the search to that one keychain (the hardware
// test's temporary keychain); production passes NULL through kwCopyMatching
// and kwDeleteItem.
static OSStatus kwCopyMatchingIn(int which, NSString *svc, NSString *acct, SecKeychainRef kc, SecKeychainRef only, CFTypeRef *result) {
    NSMutableDictionary *q = kwQuery(which, svc, acct, kc);
    if (!q) return errSecParam;
    if (only) q[(id)kSecMatchSearchList] = @[(__bridge id)only];
    return SecItemCopyMatching((__bridge CFDictionaryRef)q, result);
}

static OSStatus kwDeleteItemIn(int which, NSString *svc, NSString *acct, SecKeychainRef only) {
    NSMutableDictionary *q = kwQuery(which, svc, acct, NULL);
    if (!q) return errSecParam;
    if (only) q[(id)kSecMatchSearchList] = @[(__bridge id)only];
    return SecItemDelete((__bridge CFDictionaryRef)q);
}

static OSStatus kwCopyMatching(int which, NSString *svc, NSString *acct, SecKeychainRef kc, CFTypeRef *result) {
    return kwCopyMatchingIn(which, svc, acct, kc, NULL, result);
}

static OSStatus kwDeleteItem(int which, NSString *svc, NSString *acct) {
    return kwDeleteItemIn(which, svc, acct, NULL);
}

static const char *kwQueryNames[KW_Q_COUNT] = {
    [KW_Q_PRESENCE] = "presence",
    [KW_Q_PRESENCE_DEFAULT] = "presence in the default keychain",
    [KW_Q_REF] = "the reference delete's lookup",
    [KW_Q_DELETE] = "the delete",
    [KW_Q_FETCH_QUIET] = "the quiet read",
    [KW_Q_FETCH] = "the read behind Touch ID",
    [KW_Q_EXISTS] = "the check before an add",
    [KW_Q_LIST] = "the grant key list",
};

int kw_query_count(void) { return KW_Q_COUNT; }

const char *kw_query_name(int which) {
    if (which < 0 || which >= KW_Q_COUNT || !kwQueryNames[which]) return "";
    return kwQueryNames[which];
}

int kw_query_traits(int which) {
    @autoreleasepool {
        SecKeychainRef kc = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        if (SecKeychainCopyDefault(&kc) != errSecSuccess) {
            return -1;
        }
        NSMutableDictionary *q = kwQuery(which, @"probe", @"probe", kc);
        if (!q) {
            CFRelease(kc);
            return -1;
        }
        int traits = 0;
        if ([q[(id)kSecUseAuthenticationUI] isEqual:(id)kSecUseAuthenticationUIFail]) traits |= 1;
#pragma clang diagnostic pop
        NSArray *list = q[(id)kSecMatchSearchList];
        if (list.count == 1 && CFEqual((__bridge CFTypeRef)list[0], kc)) traits |= 2;
        if ([q[(id)kSecReturnData] boolValue]) traits |= 4;
        if ([q[(id)kSecReturnAttributes] boolValue]) traits |= 8;
        if ([q[(id)kSecReturnRef] boolValue]) traits |= 16;
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

        __block CFTypeRef result = NULL;
        __block OSStatus status;
        if (quiet) {
            // A read that must not ask (CountOpens, MatchesMEK,
            // InstallMEK; CLI only): a dialog fails the read instead.
            kwWithoutUI(^{
                status = kwCopyMatching(KW_Q_FETCH_QUIET, svc, acct, NULL, &result);
            });
        } else {
            status = kwCopyMatching(KW_Q_FETCH, svc, acct, NULL, &result);
        }
        if (status != errSecSuccess || !result) {
            if (result) CFRelease(result);
            r.status = status != errSecSuccess ? (int)status : (int)errSecItemNotFound;
            if (quiet) {
                // The quiet read's caller decides from the status
                // (keychainwrap.QuietReadError): the messages below name
                // remedies for the read behind Touch ID, which do not fit a
                // read that was never allowed to ask. A locked login
                // keychain answers it with errSecAuthFailed (measured,
                // TestHardwareLockedKeychainNeverAsks), which below would
                // read "run `jit service restart`".
                r.error_message = dupNSString([NSString stringWithFormat:@"reading the key in the keychain without asking failed, OSStatus=%d", (int)r.status]);
                return r;
            }
            // Only errSecItemNotFound actually means "no MEK stored" — the old         // old catch-all message told a user whose key EXISTS to consider
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
        // kSecUseAuthenticationUIFail (KW_Q_PRESENCE) is there for whatever
        // else could make a search ask: such a query fails with
        // errSecInteractionNotAllowed instead, and the caller reads that as
        // indeterminate. A LOCKED file keychain is not such a case: it
        // answers this query without an unlock (measured,
        // TestHardwareLockedKeychainNeverAsks).
        //
        // Returns the raw OSStatus; keychainwrap.presenceFromStatus maps it.
        return (int)kwCopyMatching(KW_Q_PRESENCE, svc, acct, NULL, NULL);
    }
}

int kw_mek_present_default(const char *service, const char *account) {
    @autoreleasepool {
        SecKeychainRef kc = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        OSStatus kcStatus = SecKeychainCopyDefault(&kc);
#pragma clang diagnostic pop
        if (kcStatus != errSecSuccess || !kc) {
            return kcStatus != errSecSuccess ? (int)kcStatus : (int)errSecNoDefaultKeychain;
        }
        OSStatus st = kwCopyMatching(KW_Q_PRESENCE_DEFAULT, [NSString stringWithUTF8String:service],
                                     [NSString stringWithUTF8String:account], kc, NULL);
        CFRelease(kc);
        return (int)st;
    }
}

int kw_item_delete(const char *service, const char *account) {
    @autoreleasepool {
        return (int)kwDeleteItem(KW_Q_DELETE, [NSString stringWithUTF8String:service],
                                 [NSString stringWithUTF8String:account]);
    }
}

// kwDeleteRefsIn is deleteItem's fallback (keychainwrap.go), taken on
// exactly errSecInvalidOwnerEdit, for one measured case
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
// The lookup carries kSecUseAuthenticationUIFail and searches only kc
// (KW_Q_REF): the default (login) keychain, where SecItemAdd put every key,
// so an item of the same name in any other keychain on the search list is
// never touched (the locked-keychain hardware test passes its own
// temporary keychain instead). The delete itself has no per-call "never
// ask" flag; that is what its two callers differ on:
//
//   - kw_item_delete_by_ref (CLI commands: the vault key's delete, a
//     rotation's promote, the move) runs it with the process's keychain
//     interaction off (kwWithoutUI).
//   - kw_item_delete_by_ref_no_switch (the service's grant and job key
//     deletes) runs it as it is: the switch is process-wide, and the
//     long-running service must not flip it under every other request in
//     flight. That is safe because the delete needs no UI on these items,
//     measured three ways: S3g row 8 (SecKeychainItemDelete on an older
//     jit's item succeeded with interaction OFF, so it needed none), S3g
//     row 9 (Apple's own `security delete-generic-password`, interaction
//     on, deleted the same item at once), and the locked-keychain test
//     (the delete by reference needs no unlock). The hardware test
//     TestHardwareGrantKeyDeleteAnOldJitsItemWithInteractionAllowed runs it
//     with interaction ON, after proving the same with it off.
//
// Returns the lookup's status when it fails (errSecItemNotFound included:
// the caller decides what an empty lookup means, and it is not "deleted"),
// else the first failing delete's, else errSecSuccess.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static OSStatus kwDeleteRefsIn(NSString *svc, NSString *acct, SecKeychainRef kc) {
    CFTypeRef result = NULL;
    OSStatus find = kwCopyMatching(KW_Q_REF, svc, acct, kc, &result);
    if (find != errSecSuccess || !result) {
        if (result) CFRelease(result);
        return find != errSecSuccess ? find : errSecItemNotFound;
    }
    NSArray *refs = (__bridge_transfer NSArray *)result;
    if (![refs isKindOfClass:[NSArray class]] || refs.count == 0) {
        return errSecItemNotFound;
    }
    OSStatus out = errSecSuccess;
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
    return out;
}
#pragma clang diagnostic pop

// kwDeleteByRefInDefault runs kwDeleteRefsIn over the default keychain,
// with the process's keychain interaction switched off around it when
// withoutUI is set.
static int kwDeleteByRefInDefault(const char *service, const char *account, int withoutUI) {
    __block OSStatus out = errSecSuccess;
    @autoreleasepool {
        NSString *svc = [NSString stringWithUTF8String:service];
        NSString *acct = [NSString stringWithUTF8String:account];
        SecKeychainRef kc = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        OSStatus kcStatus = SecKeychainCopyDefault(&kc);
#pragma clang diagnostic pop
        if (kcStatus != errSecSuccess || !kc) {
            return kcStatus != errSecSuccess ? (int)kcStatus : (int)errSecNoDefaultKeychain;
        }
        if (withoutUI) {
            kwWithoutUI(^{
                out = kwDeleteRefsIn(svc, acct, kc);
            });
        } else {
            out = kwDeleteRefsIn(svc, acct, kc);
        }
        CFRelease(kc);
    }
    return (int)out;
}

int kw_item_delete_by_ref(const char *service, const char *account) {
    return kwDeleteByRefInDefault(service, account, 1);
}

int kw_item_delete_by_ref_no_switch(const char *service, const char *account) {
    return kwDeleteByRefInDefault(service, account, 0);
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
        CFTypeRef result = NULL;
        OSStatus status = kwCopyMatching(KW_Q_LIST, [NSString stringWithUTF8String:service], @"", NULL, &result);
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

// kw_add_in_keychain adds a TEST-ONLY item to the keychain file at path (the
// hardware test's own temporary keychain), created by this binary so no
// access dialog can ever apply to it. Returns SecItemAdd's status.
int kw_add_in_keychain(const char *path, const char *service, const char *account) {
    @autoreleasepool {
        SecKeychainRef kc = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        OSStatus st = SecKeychainOpen(path, &kc);
#pragma clang diagnostic pop
        if (st != errSecSuccess || !kc) return st != errSecSuccess ? (int)st : (int)errSecNoSuchKeychain;
        NSDictionary *add = @{
            (id)kSecClass: (id)kSecClassGenericPassword,
            (id)kSecAttrService: [NSString stringWithUTF8String:service],
            (id)kSecAttrAccount: [NSString stringWithUTF8String:account],
            (id)kSecValueData: [@"probe" dataUsingEncoding:NSUTF8StringEncoding],
            (id)kSecUseKeychain: (__bridge id)kc,
        };
        st = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
        CFRelease(kc);
        return (int)st;
    }
}

// kw_probe_in_keychain runs one registry query (KW_Q_PRESENCE,
// KW_Q_FETCH_QUIET or KW_Q_DELETE), or the delete by reference (KW_Q_REF:
// kwDeleteRefsIn), against the keychain file at path alone
// (kSecMatchSearchList), with the process's keychain interaction switched
// off around it (kwWithoutUI) only when without_ui is set, and returns its
// status. For the hardware test of a LOCKED temporary keychain. A read's
// bytes are released unread.
int kw_probe_in_keychain(const char *path, const char *service, const char *account, int which, int without_ui) {
    @autoreleasepool {
        SecKeychainRef kc = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        OSStatus st = SecKeychainOpen(path, &kc);
#pragma clang diagnostic pop
        if (st != errSecSuccess || !kc) return st != errSecSuccess ? (int)st : (int)errSecNoSuchKeychain;
        NSString *svc = [NSString stringWithUTF8String:service];
        NSString *acct = [NSString stringWithUTF8String:account];
        __block OSStatus out = errSecParam;
        void (^run)(void) = ^{
            CFTypeRef result = NULL;
            switch (which) {
            case KW_Q_PRESENCE:
            case KW_Q_FETCH_QUIET:
                out = kwCopyMatchingIn(which, svc, acct, NULL, kc, &result);
                break;
            case KW_Q_DELETE:
                out = kwDeleteItemIn(which, svc, acct, kc);
                break;
            case KW_Q_REF:
                // The delete by reference (kwDeleteRefsIn), in that
                // keychain alone.
                out = kwDeleteRefsIn(svc, acct, kc);
                break;
            }
            if (result) CFRelease(result);
        };
        if (without_ui) {
            kwWithoutUI(run);
        } else {
            run();
        }
        CFRelease(kc);
        return (int)out;
    }
}
