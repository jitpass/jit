// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Package sealstore is the pure half of a sealed tool store: a CLI's own
// login state, kept in the vault and materialized into a private directory
// only while the tool runs (design/gcloud-sealed-store.md, and
// design/azure-sealed-store.md for the Azure CLI, whose Layout is Azure).
//
// The case it was built for is gcloud. Its config dir (~/.config/gcloud, or
// whatever CLOUDSDK_CONFIG names) mixes two kinds of entry:
//
//   - secrets the tool writes for itself: credentials.db (a refresh token
//     with no fixed expiry, in SQLite) and legacy_credentials/ (the same
//     token again, for bq and gsutil);
//   - settings: configurations/, active_config, logs/ and a few stamps.
//
// A FIFO cannot serve SQLite and the tool writes the store back, so jit's
// usual mount cannot protect it (spike/gcloud-sealed-config/FINDINGS.md).
// What can: point the tool's CLOUDSDK_CONFIG at a fresh private directory
// whose settings are symlinks into the real dir (writes go through, E2) and
// whose secrets are unpacked from the vault, then pack the secrets back
// after the run.
//
// This package does the file half of that and nothing else. It never
// decrypts, never reaches the vault and never runs a process; internal/cli
// (storerun.go: gcloud-run, az-run) owns those, from the stores
// migrate.ToolStores lists. A Layout names which top-level entries of a
// config dir are secret (Secrets: packed and vaulted) and which are a
// throwaway cache (Ephemeral: access_tokens.db, never vaulted, never
// carried back). Everything else is a setting.
//
// Pack is canonical — sorted entries, fixed times and owners — so two packs
// of the same content are the same bytes, and "did the run change the
// store" is a byte comparison. Unpack accepts only what Pack produces:
// regular files and directories under the layout's secret names, no links,
// no absolute or parent-relative paths.
//
// Run directories (NewRunDir, Sweep) carry their owner's pid and fork time
// in their name, so a later run can remove the dir of one that was killed
// before it cleaned up. Liveness is the caller's question (the alive
// callback), which keeps this package free of CGo and of internal/lineage.
package sealstore
