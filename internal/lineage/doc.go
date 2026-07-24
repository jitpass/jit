// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

// Package lineage is the hand-written CGo bridge to libproc(3), promoting
// spike/fifo-reader-identify/ into real code: identifying, best-effort,
// which process currently holds a live-mounted FIFO open for reading
// (RFC.md §5.1 Process Lineage Logging).
//
// Identification (IdentifyFIFOReader) is audit logging only, never a
// gate. spike/fifo-reader-identify/FINDINGS.md found a real,
// adversary-exploitable race — a reader that closes fast enough evades
// identification — and RFC.md B6 already concedes process lineage in
// general is "a speed bump and signal, not a guarantee against a
// determined local attacker who already has code execution."
// the run-scoped grant gate (internal/cli mountgrants — the decoy-by-default
// gate that actually closes GAPS.md #2) uses process ancestry only to NARROW
// a grant to one run's tree, never as the sole authority over what gets served.
//
// PathHeldOpen is the one deliberate exception to "never a gate," and it
// gates something narrower than content: whether internal/mount.Serve's
// just-served pipe needs the stale-reader isolation rename or can be
// reused (GAPS.md #47 — every needless rename is a filesystem event that
// feeds a file watcher's re-read loop). The spike's race doesn't apply
// there because the failure direction inverts: a reader that closes fast
// enough to evade the scan has, by closing, removed the very hazard the
// rename guards against — see PathHeldOpen's own doc comment for the full
// argument, including the root-only blind spot and the err-toward-held
// handling of every structural uncertainty.
//
// Deliberately the third non-portable, CGo/darwin-only package in the
// codebase, alongside internal/keychainwrap and internal/secureenclave —
// kept small and isolated the same way.
package lineage
