// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Command notarize-e2e-spike is the artifact for the notarization end-to-end
// spike: a deliberately trivial Mach-O, so that any failure in the
// sign → notarize → Gatekeeper pipeline is attributable to the account or
// Apple's notary service, never to the binary. The Aug 2026 support case
// (20000125465695) established that even a binary this trivial hangs
// "In Progress" — this spike exists to detect, repeatably and cheaply, the
// day that stops being true. See FINDINGS.md.
package main

import "fmt"

func main() {
	fmt.Println("hello from jit notarize-e2e spike")
}
