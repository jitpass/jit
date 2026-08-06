// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package vault

import "strings"

// Reserved namespaces: vault paths jit writes for its OWN bookkeeping, rather
// than secrets a user asked it to keep. Both are excluded from the surfaces
// that mean "your secrets" — List's headline count, export, completion — and a
// caller that forgets to exclude one shows migrate's undo snapshots to a user
// asking what is in their vault.
//
// These exist because the prefixes were string literals at ten call sites
// across internal/cli, internal/migrate and this package, and the OWNING
// package did not name them either: vault's own archiveVersion tested
// `strings.HasPrefix(path, "_backups/")` with the same literal every borrower
// used. A namespace whose spelling lives in ten places is not a contract, it
// is ten copies of one, and the failure on renaming it is silent in the worst
// direction — a missed site stops excluding, so backup copies of credentials
// start appearing wherever that site feeds.
//
// sanitizeSecretPath admits no path that could collide with these accidentally
// (see path.go): a real profile namespace cannot begin with an underscore.
const (
	// BackupNamespace holds `jit migrate`'s undo snapshots — the encrypted
	// copy of a file as it was before migrate rewrote it.
	BackupNamespace = "_backups"
	// HistoryNamespace holds superseded versions of a secret, shadowing the
	// live path (history.go).
	HistoryNamespace = "_history"

	// BackupPathPrefix and HistoryPathPrefix are the namespaces as a vault
	// path prefix, i.e. with the separator, for HasPrefix-style tests.
	BackupPathPrefix  = BackupNamespace + "/"
	HistoryPathPrefix = HistoryNamespace + "/"
)

// IsBackupPath reports whether p is one of `jit migrate undo`'s snapshots
// rather than a secret.
func IsBackupPath(p string) bool { return strings.HasPrefix(p, BackupPathPrefix) }

// IsHistoryPath reports whether p is an archived previous version rather than
// a live secret.
func IsHistoryPath(p string) bool { return strings.HasPrefix(p, HistoryPathPrefix) }

// IsReservedPath reports whether p lives in any namespace jit owns for its own
// bookkeeping. The test a caller listing "the user's secrets" wants, so that
// adding a third namespace later is one edit here rather than a hunt for every
// site that happened to check two.
func IsReservedPath(p string) bool { return IsBackupPath(p) || IsHistoryPath(p) }
