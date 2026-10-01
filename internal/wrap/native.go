// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package wrap

import "fmt"

// NativeDelegation describes how the CLI should serve a KindNative catalog
// entry: by running the existing migrate flow for that tool's category
// (docs/internal/WRAP-PLAN.md §3.2 — the native hook reaches SDKs and login/logout
// paths a PATH shim never sees, so wrap must not shadow it with a shim).
// This file holds routing only; the credential logic it points to lives in
// internal/migrate and is invoked at the cli layer, keeping this package
// free of a migrate import cycle.
type NativeDelegation struct {
	Tool     string
	Category string   // `jit migrate <path> --only <category>`
	Command  []string // the exact jit command the delegation runs, for display
}

// Delegation returns the migrate delegation for a KindNative entry: the
// category's own credential files, named one by one (files, from
// migrate.NativeTargets at the cli layer, which can import migrate).
// It used to name the home directory, but a directory target is walked
// for project files only, so `jit migrate ~ --only aws` answered "Nothing
// to migrate" with ~/.aws/credentials full of keys. Before that it named a
// literal "home", which failed with "./home does not exist". With no files
// there is nothing to delegate, and the error says where it looked.
func Delegation(e CatalogEntry, files []string) (NativeDelegation, error) {
	if e.Kind != KindNative {
		return NativeDelegation{}, fmt.Errorf("%s is not a native-delegated tool", e.Tool)
	}
	if len(files) == 0 {
		return NativeDelegation{}, fmt.Errorf("no %s credential file on this Mac, nothing to protect", e.Tool)
	}
	cmd := append([]string{"migrate"}, files...)
	return NativeDelegation{
		Tool:     e.Tool,
		Category: e.NativeCategory,
		Command:  append(cmd, "--only", e.NativeCategory),
	}, nil
}
