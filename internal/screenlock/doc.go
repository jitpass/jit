// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Package screenlock reports the two OS moments that mean "the human just
// left": the screen locking and the system going to sleep. The agent uses
// it to drop its session immediately instead of holding the decrypted MEK
// for the remainder of the idle TTL after the user has demonstrably walked
// away — the TTL is only ever a proxy for "the user left"; these two
// events are macOS saying so outright, and they're the same triggers the
// platform's own key holders (the Keychain, password managers' auto-lock)
// key off.
//
// Mechanism (darwin-only, C, no Objective-C needed):
//   - screen lock arrives as the "com.apple.screenIsLocked" distributed
//     notification (CFNotificationCenterGetDistributedCenter).
//   - sleep arrives via IORegisterForSystemPower. The callback MUST answer
//     kIOMessageSystemWillSleep with IOAllowPowerChange or the kernel
//     stalls the sleep for up to ~30s waiting on us; the Go handler runs
//     first, so the session is dropped before the machine is allowed down.
//
// The API is two halves — Watch (register) and RunMain (deliver) — because
// of a hard OS constraint pinned empirically during development: the
// distributed center delivers to the process's MAIN run loop only,
// regardless of which thread registered the observer. An observer
// registered on a secondary thread running its own CFRunLoop never
// receives anything; the identical registration fires the moment the main
// thread runs ITS loop. So Watch may be called from anywhere, but some
// caller must park the main OS thread in RunMain — cmd/jit locks its main
// goroutine to the main thread at init so `jit agent run` can do exactly
// that, serving connections from other goroutines as it always has.
//
// Best-effort by design, like everything else observational here: if
// registration fails, the agent still has the idle TTL, so a failure to
// watch degrades to exactly the behavior that existed before this package.
package screenlock
