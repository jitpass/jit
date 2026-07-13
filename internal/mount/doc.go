// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

// Package mount implements the re-opened named-pipe live mount (RFC.md
// Pillar III, Tiers 3-4). Re-open mechanism confirmed in spike/named-pipe/.
//
// Two content formats feed the same Serve/CreateFIFO mechanism:
// FormatDotenv generates a mount's whole content from a profile's
// resolved values (.env's own case) — the file IS entirely secrets.
// FormatTemplate instead substitutes ${VAR_NAME} placeholders into an
// otherwise-verbatim template (npmrc's Tier 4 case, GAPS.md #8) — for a
// file that mixes secrets with ordinary settings that must survive
// untouched. Entry.TemplatePath (registry.go) is empty for the first
// kind, set for the second; callers (internal/cli/agent.go's
// mountManager, jit unmount) branch on it.
//
// RFC.md B10 / GAPS.md #2: gated per-reader by process lineage, closed —
// but not the way originally planned. spike/fifo-reader-identify/
// FINDINGS.md found (a) Apple's Endpoint Security framework, the "correct"
// kernel-level way to identify a FIFO's reader, is impractical for jit's
// bare-binary/Homebrew distribution shape (a discretionary, indefinitely-
// slow entitlement that would force an app-bundle/System-Extension
// repackaging), and (b) the cheaper unprivileged libproc scan (see
// internal/lineage) has a real, adversary-exploitable timing race — a
// reader that closes fast enough evades identification. Neither is
// trustworthy enough to gate on.
//
// The actual gate is RevealState (reveal.go): a mount serves DecoyValues by
// default and only serves real content during a short, explicitly
// triggered window — trading "identify who's reading" (unreliable) for
// "bound when anyone gets something real" (doesn't need reader identity at
// all). internal/lineage's scan is still used, but only as a best-effort
// audit log layered on top (RFC.md §5.1 Process Lineage Logging), never as
// what decides what gets served.
package mount
