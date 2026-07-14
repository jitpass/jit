// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package wrap

import "fmt"

// NativeDelegation describes how the CLI should serve a KindNative catalog
// entry: by running the existing migrate flow for that tool's category
// (docs/WRAP-PLAN.md §3.2 — the native hook reaches SDKs and login/logout
// paths a PATH shim never sees, so wrap must not shadow it with a shim).
// This file holds routing only; the credential logic it points to lives in
// internal/migrate and is invoked at the cli layer, keeping this package
// free of a migrate import cycle.
type NativeDelegation struct {
	Tool     string
	Category string   // `jit migrate home --only <category>`
	Command  []string // the exact jit command the delegation runs, for display
}

// Delegation returns the migrate delegation for a KindNative entry.
func Delegation(e CatalogEntry) (NativeDelegation, error) {
	if e.Kind != KindNative {
		return NativeDelegation{}, fmt.Errorf("%s is not a native-delegated tool", e.Tool)
	}
	return NativeDelegation{
		Tool:     e.Tool,
		Category: e.NativeCategory,
		Command:  []string{"migrate", "home", "--only", e.NativeCategory},
	}, nil
}
