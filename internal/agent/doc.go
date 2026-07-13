// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

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
