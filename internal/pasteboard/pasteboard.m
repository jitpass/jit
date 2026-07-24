// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

#import "pasteboard.h"
#import <AppKit/AppKit.h>

long pb_write_concealed(const char *bytes, int len) {
    @autoreleasepool {
        NSString *s = [[NSString alloc] initWithBytes:bytes
                                               length:(NSUInteger)len
                                             encoding:NSUTF8StringEncoding];
        if (s == nil) {
            return -1; // not UTF-8; the Go side falls back to pbcopy
        }
        NSPasteboard *pb = [NSPasteboard generalPasteboard];
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

long pb_change_count(void) {
    @autoreleasepool {
        return (long)[[NSPasteboard generalPasteboard] changeCount];
    }
}

int pb_clear_if_unchanged(long change_count) {
    @autoreleasepool {
        NSPasteboard *pb = [NSPasteboard generalPasteboard];
        if ((long)[pb changeCount] != change_count) {
            return 0;
        }
        [pb clearContents];
        return 1;
    }
}
