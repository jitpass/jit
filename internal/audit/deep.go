// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
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

// vaultNeedle is one searchable needle: the vault entry, plus the gate
// verdict that would have dropped it. unfilteredReason is non-empty only
// under Config.Unfiltered, and is stamped onto every finding the needle
// produces, so a copy of a bare endpoint is marked as the configuration it
// is rather than presented as a loose credential.
type vaultNeedle struct {
	VaultNeedle
	unfilteredReason string
}

// vaultNeedles is the searchable subset of the deep scan's needles, in the
// order given. vaultNeedleSet explains what is left out and why.
func (c Config) vaultNeedles() []vaultNeedle {
	needles, _ := c.vaultNeedleSet()
	return needles
}

// vaultNeedleSet is the deep scan's needle gate: the needles to search for,
// and how many vault entries were left out as configuration.
//
// Two things are dropped, for different reasons.
//
// A value the exact-string index cannot search for safely — too short, a
// pointer, all digits — is left out by eligibleNeedle. That is a property of
// the search.
//
// A value that is self-evidently not a credential is left out by the scan's
// own name and value gates, the same pair every other scanner asks
// (NonSecretValueReason, NonSecretNameReason). That one is a judgment, and
// it is here because `jit migrate` deliberately vaults EVERY variable of a
// .env — ordinary configuration too, so the pointer file stays complete —
// and a deep scan that treats the whole vault as secrets then hunts the Mac
// for copies of an endpoint URL. A real machine (2026-09-22) had 14 of its
// 25 vault entries in that shape: CAIDO_URL, WIZ_API_ENDPOINT, JAMF_PRO_URL,
// three *_CLIENT_IDs. Every hit was a true exact match and none was an
// exposure, which is the definition of noise.
//
// This is the same overreach EnvFileCacheNeedles already fixed one layer
// down (issue #79), for the same reason and with the same pair of gates:
// eligibleNeedle tests distinctiveness, not secretness.
//
// The gates are narrow on purpose. A URL only reads as configuration when it
// carries no userinfo and no opaque segment, so a DATABASE_URL with a
// password in it, or a webhook URL with a token in its path, keeps its place
// in the search. And --unfiltered keeps every dropped needle, marking what it
// finds with the rule that fired — the filtering is never silent.
func (c Config) vaultNeedleSet() (needles []vaultNeedle, skippedAsConfig int) {
	seen := map[string]bool{}
	for _, n := range c.VaultNeedles {
		if n.Value == "" || seen[n.Value] || !eligibleNeedle(n.Value) {
			continue
		}
		suppress, reason := c.needleGate(n)
		if suppress {
			skippedAsConfig++
			continue
		}
		seen[n.Value] = true
		needles = append(needles, vaultNeedle{VaultNeedle: n, unfilteredReason: reason})
	}
	return needles, skippedAsConfig
}

// vaultNeedleCounts is what the summary records about a deep run: how many
// vault secrets were searched for, and how many were left out as
// configuration.
func (c Config) vaultNeedleCounts() (checked, skippedAsConfig int) {
	needles, skipped := c.vaultNeedleSet()
	return len(needles), skipped
}

// deepScanLine is the banner both report views print above the ledger on a
// deep run. It names what was searched for and, when the gates left
// something out, what was not — "11 vault secrets checked" against a vault
// of 25 is a difference the reader is owed, not a footnote.
func deepScanLine(summary ScanSummary) string {
	noun := "secrets"
	if summary.VaultSecretsChecked == 1 {
		noun = "secret"
	}
	line := fmt.Sprintf("  deep scan: %d vault %s checked for exact copies in the open\n",
		summary.VaultSecretsChecked, noun)
	if summary.VaultConfigSkipped > 0 {
		line += fmt.Sprintf("  %d more read as configuration and were not searched for; --unfiltered includes them\n",
			summary.VaultConfigSkipped)
	}
	return line + "\n"
}

// needleGate asks the value gate first and the name gate second, exactly as
// the env scanner does: the value is the better evidence, and a name rule
// should not excuse a variable whose value is plainly a credential.
//
// The name it judges is the variable, not the vault path — the gate's rules
// are written about variable names ("*_FILE", "CLIENT_ID"), and a vault
// namespace is the user's folder name, not evidence about the value.
func (c Config) needleGate(n VaultNeedle) (suppress bool, reason string) {
	if suppress, reason := c.valueGate(n.Value); suppress || reason != "" {
		return suppress, reason
	}
	return c.nameGate(vaultVarName(n.Name))
}

// vaultVarName is the variable at the end of a vault path:
// "wiz/WIZ_AUTH_URL" is WIZ_AUTH_URL. A path with no separator is already
// the name.
func vaultVarName(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[i+1:]
	}
	return path
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
func (c Config) vaultCopyFinding(path, agent string, n vaultNeedle, data []byte, at, count int, textual bool) Finding {
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
	if n.unfilteredReason != "" {
		// The everyday scan does not search for this value at all: the
		// gates read it as configuration. Say which rule, rather than
		// present an endpoint URL as a credential in the open.
		f.UnfilteredOnly = true
		f.UnfilteredReason = n.unfilteredReason
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
