// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/auditlog"
)

// historyLog is the durable half of the agent's session history: one JSON
// line per SessionEvent, appended as they happen, read back at the next
// startup to seed the in-memory ring (agent.Server.SeedHistory).
//
// It exists because the ring dies with the process and the process dies at
// every login — launchd restarts it — which is exactly when "why was it
// prompting me all afternoon?" gets asked: the next morning, about
// yesterday. The prose agent.log has carried these events for a while, but
// prose is for humans reading the log; this is for the agent itself (and
// --format json) to restore structured events without parsing sentences.
//
// Bookkeeping, not secret material: the same provenance the agent already
// writes to agent.log, in the same directory, same 0600.
type historyLog struct {
	path   string
	stderr io.Writer

	mu sync.Mutex
}

// historyFileName is the durable session-history file's basename under the
// config root. Named once so the writer here and the follower in `jit audit`
// (readAppended) agree on it without hardcoding the string twice.
const historyFileName = "agent-history.jsonl"

func newHistoryLog(root string, stderr io.Writer) *historyLog {
	// The agent's very first start on a fresh machine runs before anything
	// has created the config root (Server.Listen does it, but later) — and
	// the first event written is exactly that start. Best-effort like every
	// write here; a failure surfaces on the append instead.
	_ = os.MkdirAll(root, 0o700)
	return &historyLog{path: filepath.Join(root, historyFileName), stderr: stderr}
}

// historyMaxBytes bounds the file. Half is kept on trim, so the file
// oscillates between ~1MB and 2MB — at ~200 bytes per event that's ~10k
// events retained even right after a trim, years of ordinary use, for less
// disk than one photo. Raised from 512KB when this file became the SOLE home
// of session events (they used to be double-written as prose into agent.log,
// which carried a much larger 5MB cap): `jit audit` now reads only here, so
// the depth that was effectively in agent.log lives here instead.
//
// Mount serves (KindServe) are the one kind that could plausibly test this,
// since a file watcher re-reads a mount without limit. They can't, because
// they are collapsed over serveAuditWindow before they are written: one mount
// pinned by one looping reader costs ~24 events a day at the absolute worst,
// so even that pathological case retains a year rather than evicting the
// unlocks. That bound is the whole reason serveAuditor exists — see its file.
const historyMaxBytes = 2 * 1024 * 1024

// append writes one event as a JSON line. Open-per-append on purpose: events
// arrive at human pace (unlocks, grants, and mount serves already collapsed
// to at most one per mount/reader per serveAuditWindow), and never holding an
// fd means a trim (or a curious user truncating the file by hand) can't
// strand writes behind a stale offset. Failures are logged and swallowed —
// durable history is a nicety, and a full disk must never make an unlock fail.
func (h *historyLog) append(e agent.SessionEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	line, err := json.Marshal(e)
	if err != nil {
		fmt.Fprintf(h.stderr, "jit service: recording session event: %v\n", err)
		return
	}
	f, err := os.OpenFile(h.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(h.stderr, "jit service: recording session event: %v\n", err)
		return
	}
	_, werr := f.Write(append(line, '\n'))
	cerr := f.Close()
	if werr != nil {
		fmt.Fprintf(h.stderr, "jit service: recording session event: %v\n", werr)
	} else if cerr != nil {
		fmt.Fprintf(h.stderr, "jit service: recording session event: %v\n", cerr)
	}
}

// load returns up to the newest max events, oldest first (append order —
// the order SeedHistory wants). Malformed lines are skipped, not fatal: a
// torn final line from a crash mid-append must not cost the whole history.
func (h *historyLog) load(max int) []agent.SessionEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	data, err := os.ReadFile(h.path) // #nosec G304 -- jit's own bookkeeping file under its config root
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(h.stderr, "jit service: reading session history: %v\n", err)
		}
		return nil
	}
	var out []agent.SessionEvent
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e agent.SessionEvent
		if err := json.Unmarshal(line, &e); err != nil || e.Kind == "" {
			continue
		}
		out = append(out, e)
	}
	if len(out) > max {
		out = out[len(out)-max:]
	}
	// Lines written before the agent masked By at the source can hold a
	// caller's raw secret — scrub the ones being returned with the same
	// judgement the agent now applies on record, so a poisoned legacy line
	// never renders. After the cap, not inside the decode loop: seeding the
	// ring reads a ~10k-line file to keep 200, and redacting the other 98%
	// first was pure waste. scrubLegacy is what actually removes the
	// plaintext from disk; this keeps a file it hasn't rewritten yet (an
	// upgraded CLI reading before the upgraded service ran) from leaking on
	// display in the meantime.
	for i := range out {
		out[i].By = auditlog.RedactCommandLine(out[i].By)
	}
	return out
}

// scrubLegacy rewrites the history file ONCE with every By masked, so lines
// written before the agent redacted By at the source stop existing in
// plaintext on disk — not merely on display. Without this the raw secret
// would sit in the 0600 file (and in every backup of it) until ~2MB of newer
// events pushed it out, which on a quiet machine is years. Called at service
// startup next to trim, the same single-writer window, so it never races an
// append.
//
// Lines whose By is already clean are kept byte-for-byte (no re-marshal), so
// fields written by a newer binary than this one survive. Undecodable lines
// are dropped: every reader skips them anyway, and a torn legacy line is the
// one shape that could hold a partial secret this scrub cannot judge.
func (h *historyLog) scrubLegacy() {
	h.mu.Lock()
	defer h.mu.Unlock()
	data, err := os.ReadFile(h.path) // #nosec G304 -- jit's own bookkeeping file under its config root
	if err != nil {
		return
	}
	var buf bytes.Buffer
	changed := false
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e agent.SessionEvent
		if err := json.Unmarshal(line, &e); err != nil || e.Kind == "" {
			changed = true
			continue
		}
		if red := auditlog.RedactCommandLine(e.By); red != e.By {
			e.By = red
			changed = true
			nl, err := json.Marshal(e)
			if err != nil {
				continue
			}
			buf.Write(nl)
			buf.WriteByte('\n')
			continue
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	if !changed {
		return
	}
	tmp := h.path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil { // #nosec G703 -- jit's own bookkeeping path under its config root, not external input
		fmt.Fprintf(h.stderr, "jit service: scrubbing session history: %v\n", err)
		return
	}
	if err := os.Rename(tmp, h.path); err != nil {
		fmt.Fprintf(h.stderr, "jit service: scrubbing session history: %v\n", err)
	}
}

// trim rewrites the file down to its newest half once it exceeds
// historyMaxBytes, cutting on a line boundary. Called once per agent
// startup, before any append this process makes, so it never races its own
// writer. Temp-file + rename, so a crash mid-trim leaves the original
// intact rather than a half-written history.
func (h *historyLog) trim() {
	h.mu.Lock()
	defer h.mu.Unlock()
	fi, err := os.Stat(h.path)
	if err != nil || fi.Size() <= historyMaxBytes {
		return
	}
	data, err := os.ReadFile(h.path) // #nosec G304 -- jit's own bookkeeping file under its config root
	if err != nil {
		fmt.Fprintf(h.stderr, "jit service: trimming session history: %v\n", err)
		return
	}
	keep := data[len(data)-historyMaxBytes/2:]
	if i := bytes.IndexByte(keep, '\n'); i >= 0 {
		keep = keep[i+1:]
	}
	tmp := h.path + ".tmp"
	if err := os.WriteFile(tmp, keep, 0o600); err != nil { // #nosec G703 -- jit's own bookkeeping path under its config root, not external input
		fmt.Fprintf(h.stderr, "jit service: trimming session history: %v\n", err)
		return
	}
	if err := os.Rename(tmp, h.path); err != nil {
		fmt.Fprintf(h.stderr, "jit service: trimming session history: %v\n", err)
	}
}
