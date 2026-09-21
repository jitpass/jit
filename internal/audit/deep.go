// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

// A deep scan (`jit scan --deep`) is the one bridge between the two sides
// of jit (design/scan-and-protect.md): Scan may READ the vault, never touch
// it. The vault's values arrive here as VaultNeedles — the CLI did the
// authentication — and are searched for as exact strings across every
// agent cache root and every file the scan reads anyway. A hit is a
// vault_copy finding: the variable's name, the file, the line. That reaches
// the two things a pattern cannot: a formatless secret (a database
// password), and a copy whose origin the user has already protected, so no
// finding confirms its value any more.
//
// The values live in the Config for the length of one scan. Nothing here
// writes them, logs them, or lets them reach a Finding's serialized fields
// (rawValue's contract); the progress hook is given category names, never
// a value. The package stays read-only and prompt-free — see doc.go.

// VaultNeedle is one vault secret a deep scan looks for: its vault path
// ("notion/NOTION_TOKEN") and its value.
type VaultNeedle struct {
	Name  string
	Value string
}

// vaultNeedles is the eligible subset of the deep scan's needles, in the
// order given. A value the exact-string index cannot search for safely (too
// short, a pointer, all digits) is left out; see eligibleNeedle.
func (c Config) vaultNeedles() []VaultNeedle {
	var out []VaultNeedle
	seen := map[string]bool{}
	for _, n := range c.VaultNeedles {
		if n.Value == "" || seen[n.Value] || !eligibleNeedle(n.Value) {
			continue
		}
		seen[n.Value] = true
		out = append(out, n)
	}
	return out
}

// vaultCopiesInFile runs the deep scan's exact pass over one file the
// content sweep is reading anyway: the name-gated files of the machine-wide
// walk, every file of a targeted scan, and the small agent stores
// ScanAgentStores sweeps. Binary content is searched too — an exact match
// needs no lines — and reported without a line number. Same read guards and
// size bound as the content sweep.
func (c Config) vaultCopiesInFile(path string) []Finding {
	needles := c.vaultNeedles()
	if len(needles) == 0 {
		return nil
	}
	file, err := openFile(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	if info, statErr := file.Stat(); statErr != nil || !info.Mode().IsRegular() || info.Size() > maxContentScanSize {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(file, maxContentScanSize+1))
	if err != nil || len(data) > maxContentScanSize {
		return nil
	}
	return c.vaultCopiesIn(path, "", data)
}

// vaultCopiesIn is the exact pass over bytes already in hand: one
// vault_copy per (file, needle). `agent` is the cache root's label when the
// file sits in one, "" otherwise.
func (c Config) vaultCopiesIn(path, agent string, data []byte) []Finding {
	needles := c.vaultNeedles()
	if len(needles) == 0 {
		return nil
	}
	values := make([]string, len(needles))
	for i, n := range needles {
		values[i] = n.Value
	}
	first, count, _ := newSubstrIndex(values).findAll(data)
	if len(first) == 0 {
		return nil
	}
	textual := !bytes.Contains(headOf(data), []byte{0})
	var out []Finding
	for i := range needles { // needle order, never map order: NDJSON must be stable
		at, hit := first[i]
		if !hit {
			continue
		}
		out = append(out, c.vaultCopyFinding(path, agent, needles[i], data, at, count[i], textual))
	}
	return out
}

// vaultCopyFinding builds the finding for one vaulted secret found in one
// file. Not built through ValueFinding: the value's identity is not a
// judgment here — the vault says what it is — so severity is the one a
// vaulted secret in the open earns, and only the location is derived.
func (c Config) vaultCopyFinding(path, agent string, n VaultNeedle, data []byte, at, count int, textual bool) Finding {
	f := c.baseFinding()
	f.FindingType = FindingTypeVaultCopy
	f.FilePath = path
	name := n.Name
	f.KeyName = &name
	preview := MaskValue(n.Value)
	f.ValuePreview = &preview
	f.Severity = SeverityHigh
	f.Confidence = ConfidenceHigh // an exact match is not a judgment call
	f.rawValue = n.Value
	digest := sha256.Sum256([]byte(n.Value))
	f.rawValueDigest = hex.EncodeToString(digest[:])
	if agent != "" {
		f.Agent = agent
		f.CacheArea = AgentCacheArea(c.HomeDir, path)
	}
	if textual {
		line := 1 + bytes.Count(data[:at], []byte{'\n'})
		f.Line = &line
	}
	f.Evidence = fmt.Sprintf("an exact copy of the vaulted secret %s", n.Name)
	if agent != "" {
		f.Evidence += ", kept by " + agent
	}
	if count > 1 {
		f.Evidence = fmt.Sprintf("%s (%d occurrences in this file)", f.Evidence, count)
	}
	// Manual, as a scan verdict: the secret is already in the vault, and
	// this plaintext copy is not something a file migration moves. Clean
	// Caches reaches a copy in an agent's cache; a copy in a plain file is
	// the user's to delete — and either way the value was readable, so
	// rotation leads the advice. Set here so the whole type carries one
	// answer, as agent_cached_secret does.
	f.Remedy = RemedyManual
	f.RecordID = RecordID(f.FindingType, f.FilePath, f.KeyName)
	return f
}
