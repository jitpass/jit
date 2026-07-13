#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <string.h>
#import <stdlib.h>

typedef struct {
    int success;
    char *error_message;
} LATestResult;

static char *dupNSString(NSString *s) {
    if (!s) return NULL;
    return strdup([s UTF8String]);
}

LATestResult la_challenge(const char *reason) {
    LATestResult r = {0, NULL};
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
            if (error) errMsg = [error localizedDescription];
            done = 1;
        }];

        NSDate *timeout = [NSDate dateWithTimeIntervalSinceNow:120];
        while (!done && [timeout timeIntervalSinceNow] > 0) {
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
        }

        if (!done) {
            r.error_message = strdup("timed out waiting for a response");
            return r;
        }
        if (!approved) {
            r.error_message = dupNSString(errMsg ?: @"not approved");
            return r;
        }
        r.success = 1;
    }
    return r;
}
