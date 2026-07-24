// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Package cli wires up jit's command-line surface. Each subcommand is
// added to rootCmd by the package that implements it (via init(), in its
// own file — audit.go, migrate.go, run.go, export.go, doctor.go,
// unmount.go, agent.go, awscred.go, k8scred.go, vault.go), as that
// feature landed; root.go only defines the root command and shared
// scaffolding. paths.go holds the small set of portable (non-darwin-gated)
// path helpers (vaultRootDir, openVaultReadOnly) doctor needs without
// pulling in the CGo/keychain dependency the vault-mutating commands
// (vault.go's openVault) do.
package cli
