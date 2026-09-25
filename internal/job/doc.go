// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Package job is the pure half of AI Jobs (design/agent-jobs.md): what a job
// is, where the list of them lives, how a job's folder is fingerprinted, which
// commands are refused outright, and how secret values are hidden in a run's
// output. It decrypts nothing and starts nothing. The service (internal/agent
// and its CLI wiring) does both, and leans on this package for every decision
// that does not need a key.
//
// A job is a command the human approved, with the secrets it gets. An AI tool
// asks for a job by name; the jit service runs it and hands back the output
// with the values hidden. The tool never holds a key. That one property is
// what everything here protects, and each file carries one piece of it:
//
//   - job.go: the record. Its secrets are frozen at approval as concrete vault
//     paths plus a digest of their wrapped bytes, so editing a profile later
//     can never change what a job injects (a profile file sits in a folder an
//     agent can write).
//   - store.go: jobs.json, beside grants.json in jit's own directory, which no
//     sandbox is ever given. Never in a project, for the same reason.
//   - fingerprint.go: a hash of every file the job could run, taken at
//     approval and re-taken before every run. A script, a library in its
//     .venv, or the profile manifest changed after approval stops the job
//     until the human looks. The executable is hashed too, wherever it lives.
//   - policy.go: commands refused at approval because they hand the values
//     straight back (`python -c`, `env`, `cat`). A guard against the obvious
//     mistake, never the boundary: the boundary is the human reading the
//     command before spending a Touch ID.
//   - mask.go: a streaming filter that replaces every injected value, and its
//     common encodings, with [hidden: NAME] before a byte reaches the caller,
//     including a value split across two reads.
//
// What none of it can stop, stated so no reader has to rediscover it: a script
// written to leak (posting its key somewhere, or printing it in a form the
// masker does not know). The fingerprint makes sure the code that runs is the
// code that was read. It cannot make that code honest.
package job
