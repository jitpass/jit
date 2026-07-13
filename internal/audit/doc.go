// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

// Package audit implements the read-only risk scanner (RFC.md §4, jit audit).
// The jit migrate guided fix path (task #7) is a separate command, not a
// flag on audit, so this package's Scan stays read-only in every mode; it
// reuses Scan's results rather than living inside this package.
package audit
