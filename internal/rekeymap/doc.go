// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Package rekeymap is the digest map a key rotation leaves for the jit
// service, so that AI jobs and grants approved before `jit vault rekey`
// keep working after it (design/secure-enclave-rotation.md, part 2).
//
// A job or a grant pins a secret by the SHA-256 of its wrapped data key
// (Digest). A rotation wraps the same data key again under the new master
// key, so the hash changes while the value cannot. Before it writes any
// envelope, the rotation records every change it is about to make, old hash
// to new, in rekey.digests (Write). Each change was made by a rewrap that
// proved the data key unchanged: the new wrapped bytes open, under the new
// key, to the data key the old ones opened to.
//
// The rule the service applies (Map.Reaches): a pin (P, D) moves to C only
// when C is the hash of the envelope at P now, and the map holds a chain
// D to … to C. Every link kept the same data key, so the chain proves the
// data key at P now is the approved one. A value set since the approval has
// a new data key, which no chain reaches; a pin can never move to another
// path's envelope, because C is read at P. Chains span several rotations
// the service slept through, and following one is bounded by the map's
// size, so a cycle cannot loop.
//
// The file is written whole, with internal/atomicfile, once per run and
// before the first envelope changes, merging what an earlier interrupted
// run wrote: the new wrapped bytes are random, so the old hashes can never
// be recomputed after the envelopes are written. An entry whose new hash no
// envelope has (the run stopped before writing it, and the next run wrapped
// that data key again) is harmless, since no pin can chain to it; Prune
// drops such dead ends once a run has written everything.
//
// A version this build does not know, or a file that does not parse, is an
// error: nothing is applied, and nothing writes over it.
//
// Trust: the file lives beside jobs.json and grants.json, 0600, in the
// folder sandboxed callers must never write. A program that can write it
// can already rewrite a pin directly, so the map adds no capability.
//
// Pure Go on internal/atomicfile only: the CLI writes the map and the agent
// reads it, and the agent never imports internal/vault.
package rekeymap
