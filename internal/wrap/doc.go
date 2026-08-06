// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Package wrap implements shell-plugin-style CLI wrapping (docs/internal/WRAP-PLAN.md):
// a directory of symlinks to the jit binary (~/.jit/shims), each named after
// a wrapped tool, placed first on PATH. Invoked through such a symlink, jit
// enters shim mode (ShimInvocation/ShimExec) and replaces itself with
// `jit run --profile wrap-<tool> -- <real-tool> <args...>`, so the tool's
// credential exists only inside that one process's environment.
//
// This package owns the shim lifecycle (install, manifest bookkeeping,
// undo) and the shim-mode exec path; it deliberately reuses internal/profile
// for manifests and leaves vault access to jit run.
//
// The catalog of known tools (which env var, where the plaintext token lives
// today) SHIPPED: see catalog.go for the four Kinds -- KindShim, KindNative,
// KindCapture, KindRunGrant -- and catalog_data.go for the entries, bound to
// docs/wrap/ by plugins_doc_test.go. `jit wrap add` still wraps a tool the
// user describes by hand. This paragraph said the catalog "is M2 of the plan
// and doesn't exist yet" until 2026-08-06, which told a newcomer following
// CLAUDE.md's "read the doc.go before the code" that the feature they were
// about to modify had not been built.
package wrap
