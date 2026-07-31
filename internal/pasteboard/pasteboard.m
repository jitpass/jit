// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

#import "pasteboard.h"
#import <AppKit/AppKit.h>

// pb_for resolves a name to a pasteboard: NULL/empty is the general one (every
// production call), anything else a private named board (the package's own
// test). See pasteboard.h for why the seam exists at all.
static NSPasteboard *pb_for(const char *name) {
    if (name == NULL || name[0] == '\0') {
        return [NSPasteboard generalPasteboard];
    }
    return [NSPasteboard pasteboardWithName:[NSString stringWithUTF8String:name]];
}

long pb_write_concealed(const char *name, const char *bytes, int len) {
    @autoreleasepool {
        NSString *s = [[NSString alloc] initWithBytes:bytes
                                               length:(NSUInteger)len
                                             encoding:NSUTF8StringEncoding];
        if (s == nil) {
            return -1; // not UTF-8; the Go side falls back to pbcopy
        }
        NSPasteboard *pb = pb_for(name);
        [pb clearContents];
        [pb declareTypes:@[ NSPasteboardTypeString, @"org.nspasteboard.ConcealedType" ]
                   owner:nil];
        [pb setString:s forType:NSPasteboardTypeString];
        // The concealed type's value is irrelevant; its PRESENCE is the
        // signal (nspasteboard.org).
        [pb setString:@"" forType:@"org.nspasteboard.ConcealedType"];
        return (long)[pb changeCount];
    }
}

long pb_change_count(const char *name) {
    @autoreleasepool {
        return (long)[pb_for(name) changeCount];
    }
}

int pb_has_type(const char *name, const char *type) {
    @autoreleasepool {
        NSString *t = [NSString stringWithUTF8String:type];
        for (NSPasteboardType declared in [pb_for(name) types]) {
            if ([declared isEqualToString:t]) {
                return 1;
            }
        }
        return 0;
    }
}

int pb_clear_if_unchanged(const char *name, long change_count) {
    @autoreleasepool {
        NSPasteboard *pb = pb_for(name);
        if ((long)[pb changeCount] != change_count) {
            return 0;
        }
        [pb clearContents];
        return 1;
    }
}
