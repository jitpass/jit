// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

#include "screenlock.h"

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOMessage.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <pthread.h>

// Implemented in screenlock.go (//export). Receives every event as a name:
// the distributed-notification name verbatim, or sl_power_sleep_name.
extern void goScreenLockEvent(char *name);

const char *sl_power_sleep_name = "jit.screenlock.systemWillSleep";

static void sl_distributed_cb(CFNotificationCenterRef center, void *observer,
                              CFNotificationName name, const void *object,
                              CFDictionaryRef userInfo) {
    char buf[512];
    if (name != NULL &&
        CFStringGetCString(name, buf, sizeof(buf), kCFStringEncodingUTF8)) {
        goScreenLockEvent(buf);
    }
}

void sl_observe_distributed(const char *name) {
    CFStringRef n =
        CFStringCreateWithCString(NULL, name, kCFStringEncodingUTF8);
    if (n == NULL) {
        return;
    }
    CFNotificationCenterAddObserver(
        CFNotificationCenterGetDistributedCenter(), NULL, sl_distributed_cb,
        n, NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
    CFRelease(n);
}

void sl_post_distributed(const char *name) {
    CFStringRef n =
        CFStringCreateWithCString(NULL, name, kCFStringEncodingUTF8);
    if (n == NULL) {
        return;
    }
    CFNotificationCenterPostNotification(
        CFNotificationCenterGetDistributedCenter(), n, NULL, NULL, true);
    CFRelease(n);
}

static io_connect_t sl_root_port;

static void sl_power_cb(void *refCon, io_service_t service,
                        natural_t messageType, void *messageArgument) {
    switch (messageType) {
    case kIOMessageCanSystemSleep:
        // "May I sleep?" — never veto; jit has no business keeping a
        // laptop awake.
        IOAllowPowerChange(sl_root_port, (long)messageArgument);
        break;
    case kIOMessageSystemWillSleep:
        // Deliver to Go FIRST (synchronously — the session is dropped
        // before this returns), then release the sleep. Skipping the
        // IOAllowPowerChange would stall the machine's sleep for up to
        // ~30s waiting on us.
        goScreenLockEvent((char *)sl_power_sleep_name);
        IOAllowPowerChange(sl_root_port, (long)messageArgument);
        break;
    default:
        break;
    }
}

void sl_watch_power(void) {
    IONotificationPortRef notifyPort;
    io_object_t notifier;
    sl_root_port =
        IORegisterForSystemPower(NULL, &notifyPort, sl_power_cb, &notifier);
    if (sl_root_port == MACH_PORT_NULL) {
        return; // best-effort: the idle TTL still covers sleep, just later
    }
    // Explicitly the MAIN loop, matching where the distributed center
    // delivers, so one parked thread serves both sources.
    CFRunLoopAddSource(CFRunLoopGetMain(),
                       IONotificationPortGetRunLoopSource(notifyPort),
                       kCFRunLoopCommonModes);
}

int sl_is_main_thread(void) { return pthread_main_np(); }

void sl_run_main(void) { CFRunLoopRun(); }

void sl_stop_main(void) {
    CFRunLoopRef main = CFRunLoopGetMain();
    // PerformBlock (not a bare CFRunLoopStop) closes the stop/run race: a
    // stop that arrives before the loop has entered its run would be a
    // no-op, stranding sl_run_main forever. Queued as a block, it executes
    // the moment the loop starts instead.
    CFRunLoopPerformBlock(main, kCFRunLoopCommonModes, ^{
        CFRunLoopStop(main);
    });
    CFRunLoopWakeUp(main);
}
