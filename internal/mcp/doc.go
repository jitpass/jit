// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Package mcp is `jit mcp`: a Model Context Protocol server over stdio that
// lets an AI app list and run AI jobs (design/agent-jobs.md). It exists for
// apps whose shell cannot run jit itself: Claude Desktop's Cowork runs in a
// Linux VM, but Claude Desktop starts local stdio MCP servers on the Mac and
// bridges their tools into the VM. That bridge is the one door from the VM to
// a host process the user chose.
//
// What it trusts, and what it never does, is the whole of its design:
//
//   - It trusts nothing the model sends except a job NAME, which it passes
//     to the service unchanged, and a job PROPOSAL, which it validates and
//     turns into a sentence for the human. Everything else is ignored.
//   - It never unwraps a key, never reads a secret, never writes a file and
//     never starts a command. It is a socket client of the jit service, and
//     every decision (the fingerprint, the prompt, the masking) happens
//     there. A job run through here and one run with `jit job run` are the
//     same RPC, so the two paths cannot drift.
//   - It holds no secret to lose. What it relays is the job's output after
//     the service replaced every hidden value.
//
// The protocol is hand-rolled over encoding/json: JSON-RPC 2.0, one message
// per line, and four methods (initialize, ping, tools/list, tools/call).
// TECH_STACK.md §2 treats dependencies as a threat-model question, and that
// matters more than usual for the one jit process a model talks to directly.
package mcp
