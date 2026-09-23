// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Package agent implements the jit-agent session broker (RFC.md Pillar
// II): a Unix-socket server (Server) holding the decrypted MEK in memory
// for up to a TTL after the most recent use (a sliding inactivity
// timeout, GAPS.md #45), and a Client other jit
// processes use to share that session instead of each prompting Touch ID
// independently. Peer connections are verified same-user (peercred.go —
// the mechanism confirmed in spike/unix-socket-peercred/) before anything
// is served.
//
// Server is also usable directly as a vault.KeyWrapper (structurally, no
// import of internal/vault here) for the agent process's own in-process
// use serving .env mounts (internal/mount) — see its doc comment for why
// mount-serving is deliberately NOT tied to the session's lock state.
//
// The CLI wiring (install/uninstall as a launchd LaunchAgent, unlock/lock/
// status, and the long-running `jit agent run` that actually starts
// Server and serves mounts) lives in internal/cli/agent.go, not here.
package agent

// # Grants, and the one piece of state that outlives this process
//
// A process grant (grant.go, design/process-grants.md) is a scoped cache of
// plaintext DEKs in mlocked memory, anchored to a live pid and bounded by a
// deadline. It dies with the process, and since 2026-09-23 it says so: a
// clean stop ends every one of them with cause "ended when the service
// stopped" before the event streams close.
//
// A STANDING grant (standing.go, design/standing-grants.md) is the one thing
// this package keeps across restarts, and it is therefore the one thing here
// that touches disk. It has no deadline. At creation, under the same
// disclosed challenge, each covered DEK is re-wrapped under a per-grant key
// held in the keychain (service "com.jitpass.grant.key", account = grant id),
// and the wrapped copies go to a ledger beside the vault
// (GrantLedgerPath, mode 0600). Serving needs that key alone: no MEK, no
// session, no prompt. It ends only on revoke, which deletes the key and so
// makes the ledger's copies unrecoverable.
//
// Two consequences worth knowing before reading the code. The anchor is an
// executable path plus a program name rather than a pid, because a pid
// cannot survive the reboot the grant exists to survive; what that trades is
// argued in the design note, not here. And nothing secret is written: the
// ledger holds material wrapped under a key that is not in it, the same
// trust tier as the vault's own envelopes and the master key.
