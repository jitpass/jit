// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Package audit implements the read-only risk scanner (RFC.md §4, jit scan).
// The jit migrate guided fix path is a separate command, not a
// flag on audit, so this package's Scan stays read-only in every mode; it
// reuses Scan's results rather than living inside this package.
//
// A deep scan (Config.VaultNeedles, `jit scan --deep`) does not bend that:
// the vault's values arrive as inputs the CLI authenticated for, are searched
// for as exact strings, and leave as names and locations only (deep.go).
// Reading the vault is the caller's act; this package still writes nothing
// and prompts for nothing.
package audit
