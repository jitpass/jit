// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Package auditlog is jit's application audit trail: a durable, append-only
// record of every jit command a user ran, what command, when, by whom, from
// what parent process, and whether it succeeded. It is the "what happened on
// this machine" companion to the agent's session history (which records the
// auth side: which unlocks and denials happened, and what launched them). The
// two are merged by `jit audit` into one timeline.
//
// It is bookkeeping, never secret material. Command arguments are passed
// through Redact before they are written, so a value that looks like a secret
// (an API key typed on the command line, say) is masked to a fixed token
// rather than persisted in the clear. The log records that a command RAN, not
// the secret it may have carried.
//
// The file lives alongside the vault, same 0600 posture as agent.log and
// agent-history.jsonl, and is bounded the same way (trim to the newest half
// once it grows past a cap), so it costs a bounded amount of disk forever.
package auditlog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// Record is one jit command invocation. Everything here is either kernel- or
// runtime-derived (uid, pids) or the command's own resolved identity, none of
// it is secret, and Args is redacted before it ever reaches a Record that gets
// written (see Redact).
type Record struct {
	// UnixNano is when the invocation finished, in nanoseconds. Nanoseconds
	// (not seconds like the agent's SessionEvent) because a scripted burst of
	// jit commands can run several within one second, and an audit trail that
	// collapses their order is worth less exactly when it matters most.
	UnixNano int64 `json:"unix_nano"`
	// Command is the resolved cobra command path, e.g. "jit vault get", the
	// stable identity to filter on, independent of how the args were spelled.
	Command string `json:"command"`
	// Args is the invocation's arguments (os.Args without the program name),
	// redacted: any token that looks like a secret value is masked. Kept so the
	// log answers "what exactly was run", not just "which subcommand".
	Args []string `json:"args,omitempty"`
	// User and UID identify who ran it. Both are recorded because a username
	// can be reassigned to a different uid over a machine's life, and an audit
	// trail should survive that.
	User string `json:"user,omitempty"`
	UID  int    `json:"uid"`
	// PID is this jit process; PPID its parent. Parent is the parent's
	// human-readable name ("claude", "Code", a shell) and LaunchedBy the
	// nearest ancestor that actually explains the call, both best-effort, the
	// same "who really asked for this" the agent records for its own prompts.
	PID        int    `json:"pid"`
	PPID       int    `json:"ppid"`
	Parent     string `json:"parent,omitempty"`
	LaunchedBy string `json:"launched_by,omitempty"`
	// DurationMS is how long the command took, milliseconds.
	DurationMS int64 `json:"duration_ms"`
	// Success is whether the command exited without an error; Error is a short,
	// redacted summary when it didn't (never a full stack, and run through the
	// same masking as Args in case an error echoes an argument back).
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	// Auth names the authentication this invocation performed, when it forced
	// its own fresh local user-presence challenge (Touch ID/passcode) rather
	// than riding a cached agent session — the plaintext-restoring and
	// destructive migrate commands (`jit migrate undo`, `jit migrate remove`)
	// do this so an attacker can't reuse an unlocked session to exfiltrate or
	// destroy secrets. Empty for everything else, so the field's presence is
	// itself the signal that a fresh fingerprint gated the action.
	Auth string `json:"auth,omitempty"`
}

// Logger appends Records to a JSONL file and reads them back. Concurrency-safe
// for the rare case of two jit processes writing at once (each append is a
// single write to an O_APPEND fd, so lines never interleave).
type Logger struct {
	path   string
	stderr io.Writer
	mu     sync.Mutex
}

// FileName is the audit log's basename under the config root. Exported so a
// reader (jit audit) and doctor can name it without hardcoding the string
// twice.
const FileName = "audit.jsonl"

// New builds a Logger writing to root/audit.jsonl. stderr receives the
// occasional best-effort write failure; a nil stderr discards them.
func New(root string, stderr io.Writer) *Logger {
	if stderr == nil {
		stderr = io.Discard
	}
	// Best-effort like every write here: the very first jit command on a fresh
	// machine may run before anything created the config root.
	_ = os.MkdirAll(root, 0o700)
	return &Logger{path: filepath.Join(root, FileName), stderr: stderr}
}

// maxBytes bounds the file; trim keeps the newest half. At ~250 bytes per
// record that is still thousands of commands retained right after a trim.
const maxBytes = 512 * 1024

// Append writes one record as a JSON line. Open-per-append on purpose: audit
// records are infrequent, and never holding an fd means a trim (or a user
// truncating the file by hand) can't strand writes behind a stale offset.
// Failures are logged and swallowed: the audit trail is a nicety and a full
// disk must never make the command that was about to be recorded fail after it
// already ran.
func (l *Logger) Append(r Record) {
	l.mu.Lock()
	defer l.mu.Unlock()
	line, err := json.Marshal(r)
	if err != nil {
		fmt.Fprintf(l.stderr, "jit: recording audit event: %v\n", err)
		return
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(l.stderr, "jit: recording audit event: %v\n", err)
		return
	}
	_, werr := f.Write(append(line, '\n'))
	cerr := f.Close()
	if werr != nil {
		fmt.Fprintf(l.stderr, "jit: recording audit event: %v\n", werr)
	} else if cerr != nil {
		fmt.Fprintf(l.stderr, "jit: recording audit event: %v\n", cerr)
	}
}

// Load returns up to the newest max records, oldest first. A max <= 0 returns
// everything. Malformed lines are skipped, not fatal: a torn final line from a
// crash mid-append must not cost the whole log.
func (l *Logger) Load(max int) []Record {
	l.mu.Lock()
	defer l.mu.Unlock()
	data, err := os.ReadFile(l.path) // #nosec G304 -- jit's own bookkeeping file under its config root
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(l.stderr, "jit: reading audit log: %v\n", err)
		}
		return nil
	}
	var out []Record
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil || r.Command == "" {
			continue
		}
		out = append(out, r)
	}
	if max > 0 && len(out) > max {
		out = out[len(out)-max:]
	}
	return out
}

// Trim rewrites the file down to its newest half once it exceeds maxBytes,
// cutting on a line boundary. Temp-file + rename, so a crash mid-trim leaves
// the original intact rather than a half-written log. Cheap to call before
// each append; a stat that shows the file is small returns immediately.
//
// The mutex serializes trim and append within one process, but every jit CLI
// invocation is a separate process with its own Logger, so a trim in one can
// rename the file out from under an append fd another already opened, and that
// one record is lost to the orphaned inode. The window only opens once the
// file is over maxBytes, and this trail is best-effort by contract (a lost
// bookkeeping line must never fail the command that ran), so it is left as a
// known, bounded gap rather than paid for with cross-process file locking.
func (l *Logger) Trim() {
	l.mu.Lock()
	defer l.mu.Unlock()
	fi, err := os.Stat(l.path)
	if err != nil || fi.Size() <= maxBytes {
		return
	}
	data, err := os.ReadFile(l.path) // #nosec G304 -- jit's own bookkeeping file under its config root
	if err != nil {
		fmt.Fprintf(l.stderr, "jit: trimming audit log: %v\n", err)
		return
	}
	keep := data[len(data)-maxBytes/2:]
	if i := bytes.IndexByte(keep, '\n'); i >= 0 {
		keep = keep[i+1:]
	}
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, keep, 0o600); err != nil { // #nosec G306 G703 -- jit's own bookkeeping path under its config root, not attacker-controlled
		fmt.Fprintf(l.stderr, "jit: trimming audit log: %v\n", err)
		return
	}
	if err := os.Rename(tmp, l.path); err != nil {
		fmt.Fprintf(l.stderr, "jit: trimming audit log: %v\n", err)
	}
}

// RedactToken is the fixed placeholder a masked secret becomes. Fixed (not
// length-preserving stars) so the log never leaks even the length of what was
// masked.
//
// Exported because internal/cli masks one more argument this package cannot
// see (the trailing value of a `jit vault set`-shaped command, auditrecord.go)
// and was retyping the literal to do it. Two producers of one placeholder, and
// a divergence puts a real value in the log looking like a mask.
const RedactToken = "<redacted>"

// secretPrefixes are the well-known "this is unambiguously a live credential"
// leaders. A token starting with one is masked whole regardless of length or
// entropy, these are never a path, a flag, or a vault label.
// Kept in sync with internal/audit's knownTokenPatterns by
// TestEveryRecognizedFormatIsRedactedInTheAuditLog, which derives each
// pattern's literal prefix and asserts a SHORT token of that format is masked
// here. The entropy floor below rescues most credentials whatever their
// prefix, but only above 24 characters — a shorter token of a recognized
// format would otherwise be written to the log in the clear, which is the one
// thing this log promises never to do. The guard uses a deliberately short
// body so it fails unless the prefix itself is listed.
//
// The two lists stay separate on purpose: auditlog is a leaf package the agent
// links, and importing the scanner for one slice of strings would be a poor
// trade. The test is what keeps them honest.
var secretPrefixes = []string{
	"sk-", "sk_", "pk_", "rk_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_",
	"github_pat_", "glpat-", "xoxb-", "xoxp-", "xoxa-", "xoxr-", "xapp-", "xwfp-",
	"AKIA", "ASIA", "AIza", "ya29.", "AGPA", "shpat_", "shpss_",
	"npm_", "dop_v1_", "dckr_pat_", "hf_", "sk-ant-",
	// GitLab issues a distinct prefix per token class; glpat- above is only
	// the personal one.
	"gldt-", "glrt", "glcbt-", "glptt-", "gloas-", "glagent-", "glft-",
	// Package registries and vendor formats the scanner recognizes.
	"pypi-", "ntn_", "secret_", "SG.", "whsec_", "sb_secret_", "glsa_",
	"dp.st.", "hvs.", "hvb.", "hvr.", "AGE-SECRET-KEY-", "crsr_", "tvly-",
	// A JWT's header is always base64 of {"alg":... — "eyJ" is the whole
	// format's tell, and a bare JWT in a log line is a live session.
	"eyJ",
}

// highEntropyLen is the floor for the opaque-credential heuristic: a run of
// the base64/hex/token alphabet at least this long, with both letters and
// digits, is credential-shaped. The floor keeps ordinary identifiers, vault
// labels ("stripe/live-key"), and flag values ("prod") from tripping it.
const highEntropyLen = 24

// tokenAlphabet matches one bare credential-alphabet token (no path separators,
// quotes, or spaces). Used by RedactText to find secret cores INSIDE free-form
// text, so a token wrapped in quotes or parentheses ("sk_live_…") is still
// found; the surrounding punctuation is simply not part of the match.
var tokenAlphabet = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9+/=_.-]{2,}`)

// looksSecretToken reports whether a bare token (already stripped of any
// surrounding punctuation) is credential-shaped: a well-known live-credential
// prefix, or a long high-entropy run with mixed letter/digit classes.
func looksSecretToken(tok string) bool {
	for _, p := range secretPrefixes {
		if strings.HasPrefix(tok, p) {
			return true
		}
	}
	return LooksHighEntropy(tok)
}

// LooksHighEntropy reports whether tok is a credential-shaped opaque run: long
// enough, drawn entirely from the credential alphabet, and mixing letters with
// digits. It is the prefix-independent half of looksSecretToken, exported so
// the scanner can reuse this exact judgement instead of growing a second
// entropy heuristic that would drift from this one — the way secretPrefixes
// and knownTokenPatterns already did.
//
// Callers outside the log should pair it with their own context: this says
// "opaque and credential-shaped", not "secret". A commit SHA and a correlation
// ID satisfy it too, which is fine for a redactor that would rather mask a
// non-secret than persist a real one, and NOT fine for a scanner that has to
// justify every finding to a human.
func LooksHighEntropy(tok string) bool {
	return len(tok) >= highEntropyLen && tokenAlphabet.FindString(tok) == tok && hasMixedClasses(tok)
}

// looksSecret reports whether a whole CLI argument should be masked.
// Conservative in one direction only: it would rather mask a long
// random-looking non-secret than persist a real credential, because the log's
// whole promise is that it never becomes a place secrets sit in the clear.
func looksSecret(arg string) bool {
	// A path or a flag is never a secret value, exclude them before the
	// entropy test so "/Users/me/.aws/credentials" and "--format" survive,
	// unless they carry a known credential prefix regardless.
	if strings.HasPrefix(arg, "-") || strings.ContainsAny(arg, "/ ") {
		for _, p := range secretPrefixes {
			if strings.HasPrefix(arg, p) {
				return true
			}
		}
		return false
	}
	return looksSecretToken(arg)
}

// RedactText masks every secret-looking substring inside a free-form string
// (a command's error message, say), regardless of surrounding punctuation.
// The argument-token path (Redact) sees clean tokens, but an error that echoes
// an argument back can wrap it in quotes or a sentence, and the log must not
// leak it there either.
func RedactText(s string) string {
	return tokenAlphabet.ReplaceAllStringFunc(s, func(tok string) string {
		if looksSecretToken(tok) {
			return RedactToken
		}
		return tok
	})
}

// RedactCommandLine masks secrets inside a whole command line recorded as ONE
// string — the agent's SessionEvent.By, a caller's argv joined with spaces —
// the one recorded shape Redact (which sees jit's own parsed args) never
// covers. Two passes: the vault-set grammar mask (a weak value — "hunter2" —
// is not credential-shaped and would survive every heuristic), then redactArg
// on each field, the same KEY=VALUE-splitting, path-exempting judgement
// Redact applies to jit's own os.Args. Fields redactArg keeps and that carry
// no path separator get one more RedactText sweep, so a credential wrapped in
// quotes or glued to punctuation is still found; path-bearing fields skip it
// because the entropy test has no business inside "/opt/homebrew/Cellar/…" —
// an investigator needs the program back, and looksSecret's prefix check has
// already had its chance at a path that really is a credential.
//
// Whitespace is normalized to single spaces (the fields are re-joined). By
// strings are argv joined with single spaces already, so nothing observable
// changes.
//
// This lives here rather than beside the agent that records By or the CLI
// that re-reads it, because both need the identical judgement and auditlog is
// the leaf they already share for exactly this doctrine.
func RedactCommandLine(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return line
	}
	fields, _ = MaskVaultSetValues(fields)
	for i, f := range fields {
		if f == RedactToken {
			continue
		}
		if r := redactArg(f); r != f {
			fields[i] = r
			continue
		}
		if !strings.Contains(f, "/") {
			fields[i] = RedactText(f)
		}
	}
	return strings.Join(fields, " ")
}

// MaskVaultSetValues replaces the value positionals of a `jit vault set
// <path> <value>` argv with RedactToken, reporting whether anything was
// masked. The grammar's own words — the program (matched on its base name,
// argv[0] is usually an absolute path), "vault", "set", and the path — stay
// legible: the path is the one part of the line an investigation needs, and
// it is not a secret. EVERY element past the path is masked, not just the
// last: a value argv element containing spaces rejoins as several fields, a
// mistyped extra argument is more likely a mis-pasted secret than anything
// the trail should keep, and a dash-prefixed token past the path is masked
// too unless it is one of the command's own boolean flags — a value that
// happens to start with "-" must not slip through by looking like a flag.
// After a bare "--" even a flag-spelled token is a value, exactly as cobra
// reads it.
//
// Exported because the two producers of this judgement — RedactCommandLine
// here and cli/auditrecord.go's positional mask for jit's own os.Args — must
// share ONE grammar; they briefly held two hand-rolled copies, which
// disagreed within the first review. It works element-wise, so both a real
// argv slice (elements may contain spaces) and a Fields-split line get the
// identical treatment. A slice that is not a vault-set invocation is
// returned unchanged.
func MaskVaultSetValues(argv []string) ([]string, bool) {
	const (
		wantJit = iota
		wantVault
		wantSet
		wantPath
		masking
	)
	stage := wantJit
	terminated := false
	changed := false
	out := append([]string(nil), argv...)
	for i, f := range argv {
		if !terminated && f == "--" {
			terminated = true
			continue
		}
		flagLike := !terminated && strings.HasPrefix(f, "-") && f != "-"
		switch stage {
		case wantJit:
			if flagLike {
				continue
			}
			if filepath.Base(f) != "jit" {
				return argv, false
			}
			stage = wantVault
		case wantVault:
			if flagLike {
				continue
			}
			if f != "vault" {
				return argv, false
			}
			stage = wantSet
		case wantSet:
			if flagLike {
				continue
			}
			if f != "set" {
				return argv, false
			}
			stage = wantPath
		case wantPath:
			if flagLike {
				continue
			}
			stage = masking // f is the path; keep it
		case masking:
			if !terminated && isVaultSetFlag(f) {
				continue
			}
			out[i] = RedactToken
			changed = true
		}
	}
	if !changed {
		return argv, false
	}
	return out, true
}

// VaultSetBooleanFlags are the flags a `jit vault set` command line can
// legitimately carry, all boolean — which is what lets MaskVaultSetValues
// keep them legible while masking every other token past the path. A flag
// added to the command but not listed here is masked as if it were a value:
// over-masking, never a leak. TestVaultSetGrammarMatchesCommand (cli) walks
// the real cobra command and fails if this map drifts from it, or if the
// command ever grows a non-boolean flag this grammar could not survive.
var VaultSetBooleanFlags = map[string]bool{
	"--stdin": true,
	"--yes":   true, "-y": true,
	"--force": true, "-f": true,
	"--quiet": true,
}

// isVaultSetFlag reports whether tok spells one of vault set's own boolean
// flags, including the "--flag=true" form.
func isVaultSetFlag(tok string) bool {
	if i := strings.IndexByte(tok, '='); i > 0 {
		tok = tok[:i]
	}
	return VaultSetBooleanFlags[tok]
}

// hasMixedClasses requires both letters and digits, a lone long word
// ("informationtechnology") or a lone long number (a nanosecond timestamp) is
// not credential-shaped, so this keeps the entropy test from flagging them.
func hasMixedClasses(s string) bool {
	var letter, digit bool
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digit = true
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			letter = true
		}
	}
	return letter && digit
}

// Redact returns a copy of args with any secret-looking token masked. It
// handles two shapes: a bare token (`jit vault set path sk_live_…`) and a
// KEY=VALUE / --flag=VALUE token (`--token=sk_live_…`), masking only the value
// half of the latter so the key/flag name stays legible.
func Redact(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = redactArg(a)
	}
	return out
}

func redactArg(a string) string {
	// KEY=VALUE or --flag=VALUE: mask the value, keep the name legible.
	if eq := strings.IndexByte(a, '='); eq > 0 {
		name, val := a[:eq], a[eq+1:]
		// A base64 token that merely ends in '=' padding ("AAAA…==") is not a
		// KEY=VALUE — everything after its first '=' is just more '='. Only a
		// value with real content past the padding is a genuine assignment; a
		// padding-only tail falls through to the whole-argument test below so
		// such a token can't slip past by being mis-split.
		if strings.Trim(val, "=") != "" {
			// The value half is a value, not a positional path, so it is judged
			// by looksSecretToken — which still refuses a leading-slash path
			// (its whole-token match drops the '/') but does not wave through a
			// base64 credential just because it contains '/' or '+', the way
			// the path-shy looksSecret does for a bare argument.
			if looksSecretToken(val) {
				return name + "=" + RedactToken
			}
			return a
		}
	}
	if looksSecret(a) {
		return RedactToken
	}
	return a
}
