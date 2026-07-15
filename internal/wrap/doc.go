// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

// Package wrap implements shell-plugin-style CLI wrapping (docs/internal/WRAP-PLAN.md):
// a directory of symlinks to the jit binary (~/.jit/shims), each named after
// a wrapped tool, placed first on PATH. Invoked through such a symlink, jit
// enters shim mode (ShimInvocation/ShimExec) and replaces itself with
// `jit run --profile wrap-<tool> -- <real-tool> <args...>`, so the tool's
// credential exists only inside that one process's environment.
//
// This package owns the shim lifecycle (install, manifest bookkeeping,
// undo) and the shim-mode exec path; it deliberately reuses internal/profile
// for manifests and leaves vault access to jit run. The catalog of known
// tools (which env var, where the plaintext token lives today) is M2 of the
// plan and doesn't exist yet — M1 wraps tools the user describes by hand
// via `jit wrap add`.
package wrap
